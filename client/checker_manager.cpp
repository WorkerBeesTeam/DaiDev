#include <QDebug>
#include <QCoreApplication>
#include <QDir>
#include <QFile>

#include <QJsonArray>

#include <iostream>

#include <Das/device.h>

#include "worker.h"
#include "checker_manager.h"

namespace Das {
namespace Checker {

Q_LOGGING_CATEGORY(Log, "checker")

#define MINIMAL_WRITE_INTERVAL    50

Manager::Manager(Worker *worker, QObject *parent) :
    QObject(parent),
    b_break(false), first_check_(true),
    worker_(worker),
    scheme_(worker->prj())
{
    plugin_type_mng_ = scheme_->plugin_type_mng_;
    loadPlugins(worker);

    connect(scheme_, &Scheme::control_state_changed, this, &Manager::write_data, Qt::QueuedConnection);

    connect(scheme_, &Scripted_Scheme::checker_stop, this, &Manager::stop, Qt::QueuedConnection);
    connect(scheme_, &Scripted_Scheme::checker_start, this, &Manager::start, Qt::QueuedConnection);

    connect(scheme_, &Scripted_Scheme::change_stream_state, this, &Manager::toggle_stream, Qt::QueuedConnection);
//    connect(prj, SIGNAL(modbusRead(int,uchar,int,quint16)),
//            SLOT(read2(int,uchar,int,quint16)), Qt::BlockingQueuedConnection);
//    connect(prj, SIGNAL(modbusWrite(int,uchar,int,quint16)), SLOT(write(int,uchar,int,quint16)), Qt::QueuedConnection);

    connect(&check_timer_, &QTimer::timeout, this, &Manager::check_devices);
    //check_timer_.setInterval(interval);
    check_timer_.setSingleShot(true);

    connect(&write_timer_, &QTimer::timeout, this, &Manager::write_cache);
    write_timer_.setInterval(MINIMAL_WRITE_INTERVAL);
    write_timer_.setSingleShot(true);
    // --------------------------------------------------------------------------------

    for (Device* dev: scheme_->devices())
    {
        last_check_time_map_.insert(dev->id(), { true, 0 });
    }
    check_devices(); // Первый опрос контроллеров
    first_check_ = false;

    QMetaObject::invokeMethod(scheme_, "after_all_initialization", Qt::QueuedConnection);
}

Manager::~Manager()
{
    stop();

    for (const Plugin_Type& plugin: plugin_type_mng_->types())
        if (plugin.loader && !plugin.loader->unload())
            qCWarning(Log) << "Unload fail" << plugin.loader->fileName() << plugin.loader->errorString();
}

void Manager::loadPlugins(Worker *worker)
{
    //    pluginLoader.emplace("modbus", nullptr);
    QString type;
    QObject *plugin;
    Plugin_Type* pl_type;
    QVector<Plugin_Type> plugins_update_vect;
    bool plugin_updated;
    Checker::Interface *checker_interface;
    QJsonObject meta_data;

    QDir pluginsDir(qApp->applicationDirPath());
    pluginsDir.cd("plugins");

    std::unique_ptr<QSettings> settings;

    auto qJsonArray_to_qStringList = [](const QJsonArray& arr) -> QStringList
    {
        QStringList names;
        for (const QJsonValue& val: arr)
            names.push_back(val.toString());
        return names;
    };

    std::map<QString, QString> loaded_map;

    for (const QString& fileName: pluginsDir.entryList(QDir::Files))
    {
        std::shared_ptr<QPluginLoader> loader = std::make_shared<QPluginLoader>(pluginsDir.absoluteFilePath(fileName));
        if (loader->load() || loader->isLoaded())
        {
            meta_data = loader->metaData()["MetaData"].toObject();
            type = meta_data["type"].toString();

            if (!type.isEmpty() && type.length() < 128)
            {
                pl_type = plugin_type_mng_->get_type(type);
                if (pl_type->id() && pl_type->need_it && !pl_type->loader)
                {
                    loaded_map.emplace(type, fileName);

                    plugin = loader->instance();
                    checker_interface = qobject_cast<Checker::Interface *>(plugin);
                    if (checker_interface)
                    {
                        pl_type->loader = loader;
                        pl_type->checker = checker_interface;

                        if (meta_data.constFind("param") != meta_data.constEnd())
                        {
                            plugin_updated = false;
                            QJsonObject param = meta_data["param"].toObject();

                            QStringList dev_names = qJsonArray_to_qStringList(param["device"].toArray());
                            if (pl_type->param_names_device() != dev_names)
                            {
                                qCDebug(Log) << "Plugin" << pl_type->name() << "dev_names" << pl_type->param_names_device() << dev_names;
                                pl_type->set_param_names_device(dev_names);
                                plugin_updated = true;
                            }

                            QStringList dev_item_names = qJsonArray_to_qStringList(param["device_item"].toArray());
                            if (pl_type->param_names_device_item() != dev_item_names)
                            {
                                qCDebug(Log) << "Plugin" << pl_type->name() << "dev_item_names" << pl_type->param_names_device_item() << dev_item_names;
                                pl_type->set_param_names_device_item(dev_item_names);
                                if (!plugin_updated) plugin_updated = true;
                            }

                            if (plugin_updated)
                                plugins_update_vect.push_back(*pl_type);
                        }

                        if (!settings)
                            settings = Worker::settings();
                        init_checker(pl_type->checker, scheme_);
                        pl_type->checker->configure(settings.get());
                        continue;
                    }
                    else
                        qCWarning(Log) << "Bad plugin" << plugin << loader->errorString();
                }
            }
            else
                qCWarning(Log) << "Bad type in plugin" << fileName << type;

            loader->unload();
        }
        else
            qCWarning(Log) << "Fail to load plugin" << fileName << loader->errorString();
    }

    if (!loaded_map.empty() && Log().isDebugEnabled())
    {
        auto dbg = qDebug(Log).nospace().noquote() << "Loaded plugins:";
        for (const auto& it: loaded_map)
            dbg << "\n  - " << it.first << " (" << it.second << ')';
    }

    if (plugins_update_vect.size())
    {
        worker->update_plugin_param_names(plugins_update_vect);
    }
}

void Manager::break_checking()
{
    b_break = true;

    for (const Plugin_Type& plugin: plugin_type_mng_->types())
        if (plugin.loader && plugin.checker)
            plugin.checker->stop();
}

void Manager::stop()
{
    qCDebug(Log) << "Check stoped";

    if (check_timer_.isActive())
        check_timer_.stop();

    break_checking();
}

void Manager::start()
{
    qCDebug(Log) << "Start check";
    check_devices();
}

void Manager::check_devices()
{
    b_break = false;   

    qint64 next_shot, min_shot = QDateTime::currentMSecsSinceEpoch() + 60000, now_ms;
    for (Device* dev: scheme_->devices())
    {
        if (dev->check_interval() <= 0)
        {
            continue;
        }

        Check_Info& check_info = last_check_time_map_[dev->id()];
        now_ms = QDateTime::currentMSecsSinceEpoch();
        next_shot = check_info.time_ + dev->check_interval();

        if (next_shot <= now_ms)
        {
            if (b_break) break;

            if (dev->items().size())
            {
                if (dev->checker_type()->loader && dev->checker_type()->checker)
                {
                    if (dev->checker_type()->checker->check(dev))
                    {
                        if (!check_info.status_)
                        {
                            check_info.status_ = true;
                        }
                    }
                    else if (check_info.status_)
                    {
                        check_info.status_ = false;
                        qCDebug(Log) << "Fail check" << dev->checker_type()->name() << dev->toString();
                    }
                }
                else
                {
                    if (dev->plugin_id() == 0) // is_virtual
                    {
                        if (first_check_)
                        {
                            for (Device_Item* dev_item: dev->items())
                            {
                                if (!dev_item->is_connected())
                                {
                                    // It's only first check
                                    QMetaObject::invokeMethod(dev_item, "set_raw_value", Qt::QueuedConnection, Q_ARG(QVariant, 0));
                                    QMetaObject::invokeMethod(dev_item, "set_connection_state", Qt::QueuedConnection, Q_ARG(bool, true));
                                }
                            }
                        }
                    }
                    else
                    {
                        std::vector<Device_Item*> items;

                        for (Device_Item* dev_item: dev->items())
                        {
                            if (dev_item->is_connected())
                            {
                                items.push_back(dev_item);
                            }
                        }

                        if (!items.empty())
                        {
                            QMetaObject::invokeMethod(dev, "set_device_items_disconnect",
                                                      Q_ARG(std::vector<Device_Item*>, items));
                        }
                    }
                }
            }

            now_ms = QDateTime::currentMSecsSinceEpoch();
            check_info.time_ = now_ms;
            next_shot = now_ms + dev->check_interval();
        }
        min_shot = std::min(min_shot, next_shot);
    }

    if (b_break)
        return;

    now_ms = QDateTime::currentMSecsSinceEpoch();
    min_shot -= now_ms;
    if (min_shot < MINIMAL_WRITE_INTERVAL)
    {
        min_shot = MINIMAL_WRITE_INTERVAL;
    }
    check_timer_.start(min_shot);

    if (write_cache_.size() && !write_timer_.isActive())
        write_cache();
}

void Manager::toggle_stream(uint32_t user_id, Device_Item *item, bool state)
{
    if (!item->device())
        return;

    Plugin_Type* plugin = item->device()->checker_type();
    if (plugin && plugin->checker)
        plugin->checker->toggle_stream(user_id, item, state);
}

void Manager::write_data(Device_Item *item, const QVariant &raw_data, uint32_t user_id)
{
    if (!item || !item->device())
        return;

    std::vector<Write_Cache_Item>& cache = write_cache_[item->device()->checker_type()];

    auto it = std::find(cache.begin(), cache.end(), item);
    if (it == cache.end())
    {
        cache.push_back({user_id, item, raw_data});
    }
    else if (it->raw_data_ != raw_data)
    {
        it->raw_data_ = raw_data;
    }

    if (!b_break)
        write_timer_.start();
}

void Manager::write_cache()
{
    std::map<Plugin_Type*, std::vector<Write_Cache_Item>> cache(std::move(write_cache_));
    write_cache_.clear();

    while (cache.size())
    {
        write_items(cache.begin()->first, cache.begin()->second);
        cache.erase(cache.begin());
    }
}

void Manager::write_items(Plugin_Type* plugin, std::vector<Write_Cache_Item>& items)
{
    if (items.size() == 0)
    {
        return;
    }

    if (plugin && plugin->id() && plugin->checker)
    {        
        plugin->checker->write(items);
        last_check_time_map_[items.begin()->dev_item_->device_id()].time_ = 0;
    }
    else
    {
        std::map<Device_Item*, Device::Data_Item> device_items_values;
        const qint64 timestamp_msecs = DB::Log_Base_Item::current_timestamp();

        for (const Write_Cache_Item& item: items)
        {
            Device::Data_Item data_item{item.user_id_, timestamp_msecs, item.raw_data_};
            device_items_values.emplace(item.dev_item_, std::move(data_item));
        }

        if (!device_items_values.empty())
        {
            Device* dev = device_items_values.begin()->first->device();
            QMetaObject::invokeMethod(dev, "set_device_items_values", Qt::QueuedConnection,
                                      QArgument<std::map<Device_Item*, Device::Data_Item>>
                                      ("std::map<Device_Item*, Device::Data_Item>", device_items_values),
                                      Q_ARG(bool, true));
        }
    }
}

bool Manager::is_server_connected() const
{
    return (bool)worker_->net_protocol();
}

void Manager::send_stream_toggled(uint32_t user_id, Device_Item *item, bool state)
{
    std::shared_ptr<Ver::Client::Protocol> proto = worker_->net_protocol();
    if (proto)
        proto->send_stream_toggled(user_id, item->id(), state);
}

void Manager::send_stream_param(Device_Item *item, const QByteArray &data)
{
    std::shared_ptr<Ver::Client::Protocol> proto = worker_->net_protocol();
    if (proto)
        proto->send_stream_param(item->id(), data);
}

void Manager::send_stream_data(Device_Item *item, const QByteArray &data)
{
    std::shared_ptr<Ver::Client::Protocol> proto = worker_->net_protocol();
    if (proto)
        proto->send_stream_data(item->id(), data);
    else
        toggle_stream(0, item, false);
}

} // namespace Checker
} // namespace Das
