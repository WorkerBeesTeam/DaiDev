#ifndef DAS_DATABASE_SCHEME_H
#define DAS_DATABASE_SCHEME_H

#include <functional>

#include <QUuid>
#include <QVector>
#include <QPair>
#include <QTimeZone>

#include <Helpz/db_base.h>
#include <Helpz/db_delete_row.h>
#include <Helpz/db_thread.h>

#include <Das/db/dig_param.h>
#include <Das/db/dig_param_value.h>
#include <Das/db/dig_status.h>
#include <Das/type_managers.h>
#include <Das/param/paramgroup.h>
#include <Das/device_item.h>
#include <Das/device.h>
#include <Das/section.h>
#include <Das/timerange.h>
#include <Das/log/log_pack.h>
#include <plus/das/authentication_info.h>

#include "thread_iface.h"
//#include "log_synchronizer.h"

#include "../server_protocol.h"

namespace Das {
namespace DB {

class scheme : public Helpz::DB::Base
{
public:
    scheme(const QString& name, Helpz::DB::Thread* db_thread);
public:

    /*std::unique_ptr<LogSyncInfo[]> getLastLogSyncInfo(const QString &name)
    {
        Helpz::DB::Table table = {db_name(name) + ".das_settings", {}, {"value"}};
        QString where = "WHERE param = '%1'";

        auto get_sync_info = [&](uint8_t log_type, LogSyncInfo& info)
        {
            auto q = select(table, where.arg(log_type == LOG_VALUE ? "sync_time_of_value_log" : "sync_time_of_event_log"));
            if (q.next())
            {
                QStringList val = q.value(0).toString().split('|');
                if (val.size() == 2)
                {
                    info.id = val.at(0).toUInt();
                    info.time = val.at(1).toLongLong();
                }
            }

            if (!info.id)
            {
                q = select({log_table_name(log_type, db_name(name)), {}, {"remote_id", "date", "id"}}, "ORDER BY date DESC LIMIT 1");
                if (q.next())
                {
                    info.id = q.value(0).toUInt();
                    info.time = q.value(1).toDateTime().toMSecsSinceEpoch();
                    if (!info.id)
                        q.value(2).toUInt();
                }
            }
        };

        std::unique_ptr<LogSyncInfo[]> result(new LogSyncInfo[2]);
        //    std::pair<LogSyncInfo, LogSyncInfo> result;
        get_sync_info(LOG_VALUE, result[0]);
        get_sync_info(LOG_EVENT, result[1]);
        return result;
    }

    std::vector<QPair<uint32_t, uint32_t>> checkSyncRange(const QString &name, uint8_t log_type, const QPair<uint32_t, uint32_t> &range, qint64 date_ms)
    {
        if (range.first == 0 || range.second == 0)
            return {};

        QString where = "WHERE ";
        QVariantList values;

        if (date_ms > 0) {
            auto date = QDateTime::fromMSecsSinceEpoch(date_ms);
            if (date.isValid()) {
                where += "date > ? AND ";
                values.push_back(date);
            }
        }

        values.push_back(range.first);
        values.push_back(range.second);
        where += "remote_id >= ? AND remote_id <= ? ORDER BY remote_id ASC";
        auto q = select({log_table_name(log_type, db_name(name)), {}, {"remote_id"}}, where, values);
        if (!q.isActive())
            return {};

        std::vector<QPair<uint32_t, uint32_t>> result;
        if (!q.size())
            result.push_back(range);
        else
        {
            QPair<uint32_t, uint32_t> r = range;
            while(q.next())
            {
                r.second = q.value(0).toUInt() - 1;
                if (r.first <= r.second)
                    result.push_back(r);
                r.first = ++r.second + 1;
            }
            if (r.second < range.second)
            {
                r.first = r.second + 1;
                r.second = range.second;
                result.push_back(r);
            }
        }
        return result;
    }*/


//    qint64 getLastLogTime(const QString &name);
//    qint64 getLastEventTime(const QString &name);
//    QDateTime dateFromMsec(qint64 date_ms, const QTimeZone& tz);

//    void deffered_logChanges(const QString &name, const QVector<Log_Value_Item> &pack, std::function<void(uint32_t)> log_cb)
//    {
//        if (pack.empty()) return;

//        std::vector<QVariantList> values_pack;
//        for (const Log_Value_Item& item: pack)
//        {
//            if (item.id())
//            {
//                values_pack.push_back(logValuesFromItem(item));
//                log_cb(item.id());
//            }
//        }
//        db_thread_->add_pending_query(valueLogSql(name), std::move(values_pack));
//    }

//    void deffered_set_mode(const DIG_Mode &mode);
//    void deffered_save_status(uint32_t scheme_id, uint32_t group_id, uint32_t info_id, const QStringList& args);
//    void deffered_remove_status(uint32_t scheme_id, uint32_t group_id, uint32_t info_id);
//    void deffered_save_dig_param_value(uint32_t scheme_id, const QVector<DIG_Param_Value> &pack);

//    Code_Item get_code_info(uint32_t scheme_id, uint32_t code_id);
//    QVector<Code_Item> get_code(uint32_t scheme_id);
//    void deferred_clear_status(uint32_t scheme_id);
private:
    Helpz::DB::Thread* db_thread_;
};

class global : public scheme
{
public:
    static std::shared_ptr<global> open(const QString& name, Helpz::DB::Thread* db_thread);

    global(const QString& name, Helpz::DB::Thread* db_thread);
    using scheme::scheme;

    QVector<QPair<QUuid, QString>> getUserDevices(const QString& login, const QString& password);
    void check_auth(const Authentication_Info& auth_info, Server::Protocol_Base *info_out, QUuid &device_connection_id);
private:
};

} // namespace DB
} // namespace Das

#endif // DAS_DATABASE_SCHEME_H
