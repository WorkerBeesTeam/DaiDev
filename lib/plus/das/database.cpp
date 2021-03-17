
#include <botan/pbkdf2.h>
#include <botan/base64.h>
#include <botan/parsing.h>

#include <QtSerialBus/QModbusDataUnit>
#include <QDebug>
#include <QElapsedTimer>

#include <QJsonDocument>

#include <Helpz/db_table.h>

#include <Das/db/dig_param_value.h>
#include <Das/db/dig_status.h>
#include <Das/db/device_item_value.h>
#include <Das/db/dig_mode.h>
#include <Das/type_managers.h>
#include <Das/scheme.h>
#include <Das/device.h>

#include <Helpz/db_builder.h>

#include "database.h"

namespace Das {
namespace DB {

using namespace Helpz::DB;

Helper::Helper(QObject *parent) :
    QObject(parent), Helpz::DB::Base::Base{} {}

Helper::Helper(const Helpz::DB::Connection_Info& info, const QString &name, QObject *parent) :
    QObject(parent), Helpz::DB::Base::Base{info, name} {}

/*static*/ QString Helper::get_default_suffix(const QString &table_short_name)
{
    QString suffix;
    if (!table_short_name.isEmpty())
    {
        suffix = table_short_name;
        suffix += '.';
    }
    suffix += "scheme_id = ";
    suffix += QString::number(Schemed_Model::default_scheme_id());
    return suffix;
}

QString Helper::get_default_where_suffix(const QString& table_short_name)
{
    return "WHERE " + get_default_suffix(table_short_name);
}

/*static*/ QVector<Save_Timer> Helper::get_save_timer_vect()
{
    Base& db = Base::get_thread_local_instance();
    return db_build_list<Save_Timer>(db, get_default_where_suffix());
}

/*static*/ QVector<Code_Item> Helper::get_code_item_vect()
{
    Base& db = Base::get_thread_local_instance();
    return db_build_list<Code_Item>(db, get_default_where_suffix());
}

bool Helper::set_mode(const DIG_Mode &mode)
{
    Base& db = Base::get_thread_local_instance();
    Table table = db_table<DIG_Mode>();

    const QVariantList values { mode.timestamp_msecs(), mode.user_id(), mode.mode_id() };
    const QString where = get_default_suffix() + " AND group_id = " + QString::number(mode.group_id());
    const std::vector<uint> field_ids{DIG_Mode::COL_timestamp_msecs, DIG_Mode::COL_user_id, DIG_Mode::COL_mode_id};

    const QSqlQuery q = db.update(table, values, where, field_ids);
    if (!q.isActive() || q.numRowsAffected() <= 0)
    {
        table.field_names().removeFirst();
        if (!db.insert(table, { mode.timestamp_msecs(), mode.user_id(), mode.group_id(), mode.mode_id(), Schemed_Model::default_scheme_id() }))
            return false;
    }
    return true;
}

void Helper::fill_types(Type_Managers *type_mng)
{
    type_mng->device_item_type_mng_.set(db_build_list<Device_Item_Type>(*this, get_default_where_suffix()));
    type_mng->group_type_mng_.set(db_build_list<DIG_Type>(*this, get_default_where_suffix()));
    type_mng->dig_mode_type_mng_.set(db_build_list<DIG_Mode_Type>(*this, get_default_where_suffix()));
    type_mng->sign_mng_.set(db_build_list<Sign_Type>(*this, get_default_where_suffix()));
    type_mng->param_mng_.set(db_build_list<DIG_Param_Type>(*this, get_default_where_suffix() + " ORDER BY parent_id"));
    type_mng->dig_status_category_mng_.set(db_build_list<DIG_Status_Category>(*this, get_default_where_suffix()));
    type_mng->status_mng_.set(db_build_list<DIG_Status_Type>(*this, get_default_where_suffix()));
    if (type_mng->plugin_type_mng_)
        type_mng->plugin_type_mng_->set(db_build_list<Plugin_Type>(*this, get_default_where_suffix()));
}

void Helper::fill_devices(Scheme* scheme, std::map<uint32_t, Device_item_Group*> groups)
{
    std::map<uint32_t, Device*> device_map;
    QVector<QPair<Das::Device_Item*, uint32_t>> itemTree;
    std::map<uint32_t, Das::Device_Item*> devItems;

    auto group_it = groups.cend();

    Device* dev;
    Das::Device_Item* dev_item;

    QVector<Device> devices = db_build_list<Device>(*this, get_default_where_suffix());
    QVector<Das::Device_Item> device_items = db_build_list<Das::Device_Item>(*this, get_default_where_suffix() + " ORDER BY device_id ASC");
    QVector<Device_Item_Value> device_item_values = db_build_list<Device_Item_Value>(*this, get_default_where_suffix());

    while (devices.size())
    {
        Device device = devices.takeFirst();
        dev = scheme->add_device(std::move(device));

        for (int i = 0; i < device_items.size(); )
        {
            if (device_items.at(i).device_id() != dev->id())
            {
                ++i;
                continue;
            }

            Das::Device_Item device_item = device_items.takeAt(i);

            for (int j = 0; j < device_item_values.size(); )
            {
                if (device_item_values.at(j).item_id() != device_item.id())
                {
                    ++j;
                    continue;
                }

                Device_Item_Value value = device_item_values.takeAt(j);
                device_item.set_data(value);
            }

            dev_item = dev->create_item(std::move(device_item));

            if (dev_item->group_id())
            {
                if (group_it == groups.cend() || group_it->first != dev_item->group_id())
                    group_it = groups.find(dev_item->group_id());
                if (group_it != groups.cend())
                    dev_item->set_group(group_it->second);
            }

            if (dev_item->parent_id())
                itemTree.push_back(QPair<Das::Device_Item*, uint32_t>(dev_item, dev_item->parent_id()));

            devItems[dev_item->id()] = dev_item;

        }

        device_map[dev->id()] = dev;
    }

    for (const QPair<Das::Device_Item*, uint32_t>& child: itemTree)
    {
        for (auto&& dev_pair: device_map)
            for (Das::Device_Item* item: dev_pair.second->items())
                if (item->id() == child.second)
                {
                    child.first->set_parent(item);
                    goto next_child;
                }
        next_child:;
    }
}

void Helper::fill_section(Scheme* scheme, std::map<uint32_t, Device_item_Group*>* groups)
{
    std::map<uint32_t, Device_item_Group*> tmp_groups;
    if (!groups)
        groups = &tmp_groups;

    QVector<Section> sections = db_build_list<Section>(*this, get_default_where_suffix());
    QVector<DB::Device_Item_Group> item_groups =
            db_build_list<DB::Device_Item_Group>(*this, get_default_where_suffix() + " ORDER BY section_id ASC");
    del(db_table_name<DIG_Status>(), get_default_suffix());
    QVector<DIG_Mode> dig_modes = db_build_list<DIG_Mode>(*this, get_default_where_suffix());
    QVector<DIG_Param> dig_params = db_build_list<DIG_Param>(*this,
                                                             "LEFT JOIN das_dig_param_type gpt ON gpt.id = hgp.param_id " +
                                                             get_default_where_suffix(DIG_Param::table_short_name()) +
                                                             " ORDER BY gpt.parent_id ASC, hgp.param_id ASC");
    QVector<DIG_Param_Value> dig_param_values = db_build_list<DIG_Param_Value>(*this, get_default_where_suffix());
    QString dig_param_value;

    Section* sct;
    Device_item_Group* group;

    while (sections.size())
    {
        Section section = sections.takeFirst();
        sct = scheme->add_section(std::move(section));

        for (int i = 0; i < item_groups.size(); )
        {
            if (item_groups.at(i).section_id() != sct->id())
            {
                ++i;
                continue;
            }

            DB::Device_Item_Group item_group = item_groups.takeAt(i);
            group = sct->add_group(std::move(item_group), 0);
            groups->emplace(group->id(), group);

            for (int j = 0; j < dig_modes.size(); )
            {
                if (dig_modes.at(j).group_id() != group->id())
                {
                    ++j;
                    continue;
                }

                const DIG_Mode dig_mode = dig_modes.takeAt(j);
                group->set_mode(dig_mode.mode_id(), dig_mode.user_id(), dig_mode.timestamp_msecs());
            }

            for (int j = 0; j < dig_params.size(); )
            {
                if (dig_params.at(j).group_id() != group->id())
                {
                    ++j;
                    continue;
                }

                const DIG_Param dig_param = dig_params.takeAt(j);

                auto it = std::find_if(dig_param_values.begin(), dig_param_values.end(),
                                       [&dig_param](const DIG_Param_Value& param_value) { return param_value.group_param_id() == dig_param.id(); });

                if (it == dig_param_values.end())
                {
                    dig_param_value.clear();
                }
                else
                {
                    dig_param_value = it->value();
                    dig_param_values.erase(it);
                }

                if (!group->params()->add(dig_param, dig_param_value, &scheme->param_mng_))
                {
                    qWarning() << "Failed init dig_param" << dig_param.id()
                               << dig_param.param_id() << scheme->param_mng_.title(dig_param.param_id())
                               << dig_param_value << group->toString();
                }
            }
        }
    }
}

void Helper::init_scheme(Scheme *scheme, bool typesAlreadyFilled)
{
    if (!typesAlreadyFilled)
        fill_types(scheme);

    std::map<uint32_t, Device_item_Group*> groups;

    scheme->clear_sections();
    using namespace std::placeholders;
    fill_section(scheme, &groups);

    scheme->clear_devices();
    fill_devices(scheme, groups);
    scheme->sort_devices();

    for(const std::pair<uint32_t, Device_item_Group*>& group: groups)
        group.second->finalize();
}

/*static*/ bool Helper::check_permission(uint32_t user_id, const std::string &permission)
{
    const QString sql =
            "SELECT COUNT(*) FROM das_user u "
            "LEFT JOIN das_user_groups ug ON ug.user_id = u.id "
            "LEFT JOIN auth_group_permissions gp ON gp.group_id = ug.group_id "
            "LEFT JOIN auth_permission p ON p.id = gp.permission_id "
            "WHERE u.id = ? AND p.codename = ?";

    Base& db = Base::get_thread_local_instance();
    QSqlQuery q = db.exec(sql, {user_id, QString::fromStdString(permission)});
    return q.next() && q.value(0).toUInt() != 0;
}

/*static*/ bool Helper::is_admin(uint32_t user_id)
{
    return DB::Helper::check_permission(user_id, "change_logentry");
}

/*static*/ bool Helper::compare_passhash(const std::string &password, const std::string &hash_data) noexcept(false)
{
    // hash: pbkdf2_sha256$180000$J4uFUE2UxAjK$SqMvresLM1kwcmLkdblP3dDLeAlmZ3OL9rXZxiI2Jok=
    const std::vector<std::string> data_list = Botan::split_on(hash_data, '$');
    if (data_list.size() != 4 || data_list.at(0) != "pbkdf2_sha256")
    {
        qWarning() << "Unknown algorithm";
        return false;
    }
    const std::size_t kdf_iterations = std::stoul(data_list.at(1));
    const std::string& salt = data_list.at(2);
    const Botan::secure_vector<uint8_t> hash = Botan::base64_decode(data_list.at(3));
    const size_t PASSHASH9_PBKDF_OUTPUT_LEN = 32; // 256 bits output

    auto pbkdf_prf = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    const Botan::PKCS5_PBKDF2 kdf(pbkdf_prf.release()); // takes ownership of pointer

    const Botan::secure_vector<uint8_t> cmp = kdf.derive_key(
        PASSHASH9_PBKDF_OUTPUT_LEN, password,
        reinterpret_cast<const uint8_t*>(salt.c_str()), salt.size(),
        kdf_iterations).bits_of();

    return Botan::constant_time_compare(cmp.data(), hash.data(), std::min(cmp.size(), hash.size()));
}

} // namespace DB
} // namespace Das
