#include <Helpz/dtls_server_node.h>

#include <Das/commands.h>
#include <Das/db/device_item_value.h>

#include "server.h"
#include "database/db_thread_manager.h"
#include "database/db_scheme.h"
#include "server_protocol.h"
#include "dbus_object.h"

#include "log_saver/log_saver_controller.h"
#include "log_synchronizer.h"

namespace Das {
namespace Ver {
namespace Server {

using namespace Helpz::DB;

// ------------------------------------------------------

QString get_custom_q_array(const Table& table, int row_count)
{
    // " + (force ? QString("IGNORE ") : QString()) + "
    return "INSERT INTO " +
            table.name() + '(' + table.field_names().join(',') + ") VALUES" +
            Base::get_q_array(table.field_names().size(), row_count);
}

template<typename T>
void fill_log_data_impl(uint32_t scheme_id, QIODevice &data_dev, QString &sql, QVariantList &values_pack, int &row_count)
{
    const int dsver = Helpz::Net::Protocol::DATASTREAM_VERSION;

    QVariantList tmp_values;
    QVector<T> data;
    Helpz::parse_out(dsver, data_dev, data);
    row_count = data.size();
    for (T& item: data)
    {
        item.set_scheme_id(scheme_id);
        tmp_values = T::to_variantlist(item);
        tmp_values.removeFirst();
        values_pack += tmp_values;
    }

    auto table = db_table<T>();
    table.field_names().removeFirst(); // remove id
    sql = get_custom_q_array(table, data.size());
}

// ------------------------------------------------------

Log_Sync_Item::Log_Sync_Item(Log_Type type, Protocol_Base *protocol) :
    Base_Synchronizer(protocol),
    in_progress_(false),
    type_(type)
{
}

void Log_Sync_Item::check()
{
    if (!in_progress_)
    {
        in_progress_ = true;
        request_log_data();
    }
}

Thread *Log_Sync_Item::log_thread()
{
    return protocol()->work_object()->db_thread_mng_->log_thread();
}

void Log_Sync_Item::request_log_data()
{
    qCDebug(Sync_Log).noquote() << title() << type_.to_string() << "request_log_data";
    protocol_->send(Cmd::LOG_DATA_REQUEST).answer([this](QIODevice& /*data_dev*/)
    {
        in_progress_ = false;
    })
    .timeout([this]()
    {
        in_progress_ = false;
        qCWarning(Sync_Log).noquote() << title() << type_.to_string() << "request_log_range timeout";
    }, std::chrono::seconds(15)) << type_;
}

void Log_Sync_Item::process_log_data(QIODevice& data_dev, uint8_t msg_id)
{
    qCDebug(Sync_Log).noquote() << title() << type_.to_string() << "process_log_data";
    QString sql;
    QVariantList values_pack;
    int row_count = 0;

    try
    {
        fill_log_data(data_dev, sql, values_pack, row_count);
    }
    catch (const std::exception& e)
    {
        qCWarning(Sync_Log).noquote() << title() << type_.to_string() << "receive bad data" << e.what();
    }
    catch(...) {}

    if (!row_count)
    {
        qCWarning(Sync_Log).noquote() << title() << type_.to_string() << "receive empty data";
    }
    else
    {
        auto node = std::dynamic_pointer_cast<Helpz::DTLS::Server_Node>(protocol()->writer());
        if (!node)
        {
            qWarning(Struct_Log).noquote() << title() << "Bad node pointer process_log_data";
            return;
        }

        Log_Type_Wrapper type = type_;
        log_thread()->add([msg_id, sql, values_pack, node, type](Base* db)
        {
            std::shared_ptr<Protocol> scheme = std::dynamic_pointer_cast<Protocol>(node->protocol());

            if (db->exec(sql, values_pack).isActive())
            {
                if (scheme)
                {
                    scheme->send_answer(Cmd::LOG_DATA_REQUEST, msg_id);
                }
            }

            if (scheme && type.is_valid())
            {
                scheme->log_sync()->log_sync_item(type)->request_log_data();
            }
        });
    }

    in_progress_ = false;
}

// ------------------------------------------------------------------------------------------

Log_Sync_Values::Log_Sync_Values(Protocol_Base *protocol) :
    Log_Sync_Item(LOG_VALUE, protocol)
{
}

void Log_Sync_Values::process_pack(QVector<Log_Value_Item> &&pack, uint8_t msg_id)
{
    if (pack.empty())
        return;

    if (Log_Saver::instance()->add(protocol()->id(), pack))
        protocol()->send_answer(Cmd::LOG_PACK, msg_id);

    static_cast<Protocol*>(protocol())->structure_sync()->change_devitem_values(pack);

    QMetaObject::invokeMethod(protocol()->work_object()->dbus_, "device_item_values_available", Qt::QueuedConnection,
                              Q_ARG(Scheme_Info, *protocol_), Q_ARG(QVector<Log_Value_Item>, std::move(pack)));
}

QString Log_Sync_Values::get_param_name() const
{
    return "sync_time_of_value_log";
}

void Log_Sync_Values::fill_log_data(QIODevice& data_dev, QString &sql, QVariantList &values_pack, int &row_count)
{
    fill_log_data_impl<Log_Value_Item>(scheme_id(), data_dev, sql, values_pack, row_count);
}

// ------------------------------------------------------------------------------------------

Log_Sync_Events::Log_Sync_Events(Protocol_Base *protocol) :
    Log_Sync_Item(LOG_EVENT, protocol)
{
}

void Log_Sync_Events::process_pack(QVector<Log_Event_Item>&& pack, uint8_t msg_id)
{
    if (pack.empty())
        return;

    if (Log_Saver::instance()->add(protocol()->id(), pack))
        protocol()->send_answer(Cmd::LOG_PACK, msg_id);

    QMetaObject::invokeMethod(protocol()->work_object()->dbus_, "event_message_available", Qt::QueuedConnection,
                              Q_ARG(Scheme_Info, *protocol_), Q_ARG(QVector<Log_Event_Item>, std::move(pack)));
}

QString Log_Sync_Events::get_param_name() const
{
    return "sync_time_of_event_log";
}

void Log_Sync_Events::fill_log_data(QIODevice& data_dev, QString &sql, QVariantList &values_pack, int& row_count)
{
    fill_log_data_impl<Log_Event_Item>(scheme_id(), data_dev, sql, values_pack, row_count);
}

// ------------------------------------------------------------------------------------------

Log_Sync_Params::Log_Sync_Params(Protocol_Base *protocol) :
    Log_Sync_Item(LOG_PARAM, protocol)
{
}

void Log_Sync_Params::process_pack(QVector<Log_Param_Item> &&pack, uint8_t msg_id)
{
    if (pack.empty())
        return;

    if (Log_Saver::instance()->add(protocol()->id(), pack))
        protocol()->send_answer(Cmd::LOG_PACK, msg_id);

    QVector<DIG_Param_Value>&& param_pack = reinterpret_cast<QVector<DIG_Param_Value>&&>(pack);
    QMetaObject::invokeMethod(protocol()->work_object()->dbus_, "dig_param_values_changed", Qt::QueuedConnection,
                              Q_ARG(Scheme_Info, *protocol()), Q_ARG(QVector<DIG_Param_Value>, std::move(param_pack)));
}

void Log_Sync_Params::fill_log_data(QIODevice &data_dev, QString &sql, QVariantList &values_pack, int &row_count)
{
    fill_log_data_impl<Log_Param_Item>(scheme_id(), data_dev, sql, values_pack, row_count);
}

// ------------------------------------------------------------------------------------------

Log_Sync_Statuses::Log_Sync_Statuses(Protocol_Base *protocol) :
    Log_Sync_Item(LOG_STATUS, protocol)
{
}

void Log_Sync_Statuses::process_pack(QVector<Log_Status_Item> &&pack, uint8_t msg_id)
{
    if (pack.empty())
        return;

    if (Log_Saver::instance()->add(protocol()->id(), pack))
        protocol()->send_answer(Cmd::LOG_PACK, msg_id);

    static_cast<Ver::Server::Protocol*>(protocol())->structure_sync()->change_status(pack);

    QVector<DIG_Status>&& status_pack = reinterpret_cast<QVector<DIG_Status>&&>(pack);
    QMetaObject::invokeMethod(protocol()->work_object()->dbus_, "status_changed", Qt::QueuedConnection,
                          Q_ARG(Scheme_Info, *protocol()), Q_ARG(QVector<DIG_Status>, std::move(status_pack)));
}

void Log_Sync_Statuses::fill_log_data(QIODevice &data_dev, QString &sql, QVariantList &values_pack, int &row_count)
{
    fill_log_data_impl<Log_Status_Item>(scheme_id(), data_dev, sql, values_pack, row_count);
}

// ------------------------------------------------------------------------------------------

Log_Sync_Modes::Log_Sync_Modes(Protocol_Base *protocol) :
    Log_Sync_Item(LOG_MODE, protocol)
{
}

void Log_Sync_Modes::process_pack(QVector<Log_Mode_Item> &&pack, uint8_t msg_id)
{
    if (pack.empty())
        return;

    if (Log_Saver::instance()->add(protocol()->id(), pack))
        protocol()->send_answer(Cmd::LOG_PACK, msg_id);

    QVector<DIG_Mode>&& mode_pack = reinterpret_cast<QVector<DIG_Mode>&&>(pack);
    QMetaObject::invokeMethod(protocol()->work_object()->dbus_, "dig_mode_changed", Qt::QueuedConnection,
                              Q_ARG(Scheme_Info, *protocol()), Q_ARG(QVector<DIG_Mode>, std::move(mode_pack)));
}

void Log_Sync_Modes::fill_log_data(QIODevice &data_dev, QString &sql, QVariantList &values_pack, int &row_count)
{
    fill_log_data_impl<Log_Mode_Item>(scheme_id(), data_dev, sql, values_pack, row_count);
}

// ------------------------------------------------------------------------------------------

Log_Synchronizer::Log_Synchronizer(Protocol_Base *protocol) :
    values_(protocol),
    events_(protocol),
    params_(protocol),
    statuses_(protocol),
    modes_(protocol)
{
}

void Log_Synchronizer::check()
{
    values_.check();
    events_.check();
    params_.check();
    statuses_.check();
    modes_.check();
}

void Log_Synchronizer::process_data(Log_Type_Wrapper type_id, QIODevice *data_dev, uint8_t msg_id)
{
    switch (type_id.value())
    {
    case LOG_VALUE:    values_.process_log_data(*data_dev, msg_id); break;
    case LOG_EVENT:    events_.process_log_data(*data_dev, msg_id); break;
    case LOG_PARAM:    params_.process_log_data(*data_dev, msg_id); break;
    case LOG_STATUS: statuses_.process_log_data(*data_dev, msg_id); break;
    case LOG_MODE:      modes_.process_log_data(*data_dev, msg_id); break;
    default:
        break;
    }
}

void Log_Synchronizer::process_pack(Log_Type_Wrapper type_id, QIODevice *data_dev, uint8_t msg_id)
{
    const int dsver = Helpz::Net::Protocol::DATASTREAM_VERSION;

    switch (type_id.value())
    {
    case LOG_VALUE:
        Helpz::apply_parse(*data_dev, dsver, &Log_Sync_Values::process_pack, &values_, msg_id);
        break;
    case LOG_EVENT:
        Helpz::apply_parse(*data_dev, dsver, &Log_Sync_Events::process_pack, &events_, msg_id);
        break;
    case LOG_PARAM:
        Helpz::apply_parse(*data_dev, dsver, &Log_Sync_Params::process_pack, &params_, msg_id);
        break;
    case LOG_STATUS:
        Helpz::apply_parse(*data_dev, dsver, &Log_Sync_Statuses::process_pack, &statuses_, msg_id);
        break;
    case LOG_MODE:
        Helpz::apply_parse(*data_dev, dsver, &Log_Sync_Modes::process_pack, &modes_, msg_id);
        break;
    default:
        break;
    }
}

Log_Sync_Item *Log_Synchronizer::log_sync_item(uint8_t type_id)
{
    switch (type_id)
    {
    case LOG_VALUE:  return &values_;
    case LOG_EVENT:  return &events_;
    case LOG_PARAM:  return &params_;
    case LOG_STATUS: return &statuses_;
    case LOG_MODE:   return &modes_;
    default:
        break;
    }
    return nullptr;
}

} // namespace Server
} // namespace Ver
} // namespace Das
