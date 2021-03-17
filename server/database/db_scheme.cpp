#include <iostream>
#include <sstream>

#include <QJsonDocument>
#include <QDateTime>

#include <Helpz/settingshelper.h>
#include <Helpz/db_table.h>

#include <Das/db/device_item_value.h>
#include <plus/das/database_delete_info.h>
#include <plus/das/database.h>

#include "server.h"
#include "db_scheme.h"

namespace Das {
namespace DB {

using namespace Helpz::DB;

scheme::scheme(const QString &name, Helpz::DB::Thread* db_thread) :
    Base(Helpz::DB::Connection_Info::common(), name),
    db_thread_(db_thread)
{}

/*
qint64 scheme::getLastLogTime(const QString& name)
{
    auto q = select({db_table_name<Log_Value_Item>(db_name(name)), {}, {"date"}}, "ORDER BY date DESC LIMIT 1");
    if (q.next())
        return q.value(0).toDateTime().toMSecsSinceEpoch();
    return 0;
}

qint64 scheme::getLastEventTime(const QString &name)
{
    auto q = select({db_table_name<Log_Event_Item>(db_name(name)), {}, {"date"}}, "ORDER BY date DESC LIMIT 1");
    if (q.next())
        return q.value(0).toDateTime().toMSecsSinceEpoch();
    return 0;
}

QDateTime scheme::dateFromMsec(qint64 date_ms, const QTimeZone &tz) {
    return tz.isValid() ?
                QDateTime::fromMSecsSinceEpoch(date_ms, tz) :
                QDateTime::fromMSecsSinceEpoch(date_ms);
}

void scheme::deffered_set_mode(const DIG_Mode& mode)
{
}

void scheme::deffered_save_status(uint32_t scheme_id, uint32_t group_id, uint32_t info_id, const QStringList &args)
{
    Helpz::DB::Table table = {db_table_name<DIG_Status>(db_name(scheme_id)), {}, {"group_id", "status_id", "args"}};
    QString sql = insert_query(table, 3);

    std::vector<QVariantList> values_pack{{group_id, info_id, args.join(';')}};
    db_thread_->add_pending_query(std::move(sql), std::move(values_pack));
}

void scheme::deffered_remove_status(uint32_t scheme_id, uint32_t group_id, uint32_t info_id)
{
    QString sql = del_query(db_table_name<DIG_Status>(db_name(scheme_id)), QString("group_id = %1 AND status_id = %2").arg(group_id).arg(info_id));
    std::vector<QVariantList> values_pack;
    db_thread_->add_pending_query(std::move(sql), std::move(values_pack));
}

void scheme::deffered_save_dig_param_value(uint32_t scheme_id, const QVector<DIG_Param_Value> &pack)
{    
    if (pack.empty()) return;

    db_thread_->add([scheme_id, pack](Base* db)
    {
    });
}

Code_Item scheme::get_code_info(uint32_t scheme_id, uint32_t code_id)
{
    auto q = select({db_table_name<Code_Item>(db_name(scheme_id)), {}, {"id", "name", "global_id"}}, "WHERE id=" + QString::number(code_id));
    if (q.next())
        return Code_Item{ q.value(0).toUInt(), q.value(1).toString(), q.value(2).toUInt() };
    return {};
}

QVector<Code_Item> scheme::get_code(uint32_t scheme_id)
{
    QVector<Code_Item> code_list;
    QVariantList values;
    QStringList q_list;

    auto q = select({db_table<Code_Item>(db_name(scheme_id))});
    while( q.next() )
    {
        code_list.push_back(Code_Item{ q.value(0).toUInt(), q.value(1).toString(), q.value(2).toUInt(), q.value(3).toString() });
        Code_Item& code = code_list.back();
        if (code.global_id)
        {
            values.push_back(code.global_id);
            q_list.push_back(QChar('?'));
        }
    }

    if (!values.size())
        return code_list;

    q.finish();
    q.clear();

    q = select({"das_code", {}, {"id", "text"}}, "WHERE id IN (" + q_list.join(',') + ')', values);
    if (q.isActive())
    {
        if (q.size() != values.size())
            std::cerr << "Have not global code. Lost in global code is list" << std::endl;

        while (q.next())
            for (Code_Item& code: code_list)
                if (code.global_id == q.value(0).toUInt())
                {
                    code.text = q.value(1).toString();
                    break;
                }
    }

    return code_list;
}

void scheme::deferred_clear_status(uint32_t scheme_id)
{
    QString sql = truncate_query(db_table_name<DIG_Status>(db_name(scheme_id)));
    db_thread_->add_pending_query(std::move(sql), std::vector<QVariantList>{});
}
*/

// -----------------------------------------------------------------------------------

/*static*/ std::shared_ptr<global> global::open(const QString &name, Helpz::DB::Thread* db_thread)
{
    std::stringstream s; s << std::this_thread::get_id();

    return std::make_shared<global>(name + '_' + QString::fromStdString(s.str()), db_thread);
}

global::global(const QString &name, Helpz::DB::Thread* db_thread) :
    scheme(name, db_thread)
{}

QVector<QPair<QUuid, QString>> global::getUserDevices(const QString &login, const QString &password)
{
    auto query = select({db_table_name<User>(), {}, {"id", "password"}}, "WHERE username = ?", {login});
    if (query.next() && Helper::compare_passhash(password.toStdString(), query.value(1).toByteArray().toStdString()))
    {
        query.finish();
        query.clear();

        const QString sql =
                "SELECT s.using_key, s.title FROM das_scheme s "
                "LEFT JOIN das_scheme_groups sg ON sg.scheme_id = s.id "
                "LEFT JOIN das_scheme_group_user sgu ON sgu.group_id = sg.scheme_group_id "
                "WHERE sgu.user_id = " + query.value(0).toString();

        query = exec(sql);
        if (query.isActive())
        {
            QVector<QPair<QUuid, QString>> devices;
            QUuid device;
            while (query.next())
            {
                device = QUuid::fromRfc4122(query.value(0).toByteArray());
                if (!device.isNull())
                    devices.push_back(qMakePair(device, query.value(1).toString()));
            }
            return devices;
        }
    }

    return {};
}

void global::check_auth(const Authentication_Info &auth_info, Server::Protocol_Base *info_out, QUuid& device_connection_id)
{
    QString sql =
        "SELECT s.id, s.name, s.title, u.password, s.parent_id, s.using_key FROM das_user u "
        "LEFT JOIN das_scheme_group_user sgu ON sgu.user_id = u.id "
        "LEFT JOIN das_scheme_groups sg ON sg.scheme_group_id = sgu.group_id "
        "LEFT JOIN das_scheme s ON s.id = sg.scheme_id "
        "WHERE u.username = ? AND s.name = ?"; // AND (s.using_key IS NULL OR s.using_key = ?)

    QSqlQuery query = exec(sql, {auth_info.login(), auth_info.scheme_name()});
    if (!query.next())
    {
        qWarning() << "Cant exec auth sql. Scheme:" << auth_info.scheme_name() << "Login:" << auth_info.login();
        return;
    }

    if (!Helper::compare_passhash(auth_info.password().toStdString(), query.value(3).toByteArray().toStdString()))
    {
        qWarning() << "Password not equals. Scheme:" << auth_info.scheme_name() << "Login:" << auth_info.login()
                   << "Pwd:" << auth_info.password();
        return;
    }

    QUuid using_key = QUuid::fromRfc4122(query.value(5).toByteArray());
    if (using_key.isNull())
    {
        QSqlQuery using_key_query;
        sql = "SELECT 1 FROM das_scheme WHERE using_key = ?";
        do
        {
            using_key = QUuid::createUuid();
            using_key_query = exec(sql, { QString::fromLocal8Bit(using_key.toRfc4122().toHex()) });
        }
        while (using_key_query.next());

        QVariantList values{ QString::fromLocal8Bit(using_key.toRfc4122().toHex()), query.value(0) };
        if (!update({"das_scheme", {}, {"using_key"}}, values, "id=?").isActive())
        {
            qWarning() << "Failed create using_key for:" << auth_info.scheme_name();
//                    return;
        }
    }
    else if (using_key != auth_info.using_key())
    {
        qWarning() << "Attempt to twice connect for:" << auth_info.scheme_name();
//                return;
    }
    device_connection_id = using_key;

    info_out->set_id(query.value(0).toUInt());
    info_out->set_name(query.value(1).toString());

    std::set<uint32_t> extending_ids;
    if (!query.isNull(4)) // TODO: get array from specific table
        extending_ids.insert(query.value(4).toUInt());
    info_out->set_extending_scheme_ids(std::move(extending_ids));
//            info_out->set_scheme_title(query.value(2).toString());

    std::shared_ptr<Helpz::Net::Protocol_Writer> writer = info_out->writer();
    if (writer)
        writer->set_title(info_out->title() + " (" + info_out->name() + ')');

    std::set<uint32_t> scheme_groups;
    query.finish();
    query.clear();
    query = select({"das_scheme_groups", {}, {"scheme_group_id"}}, "WHERE scheme_id = ?", {info_out->id()});
    while (query.next())
        scheme_groups.insert(query.value(0).toUInt());
    info_out->set_scheme_groups(std::move(scheme_groups));
}

} // namespace DB
} // namespace Das
