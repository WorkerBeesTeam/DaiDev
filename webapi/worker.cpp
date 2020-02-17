#include <iostream>
//#include <filesystem>

#include <boost/asio/io_context.hpp>

#include <botan-2/botan/tls_server.h>
#include <botan-2/botan/tls_callbacks.h>

#include <QDir>

#include <Helpz/dtls_server.h>
#include <Helpz/dtls_server_thread.h>
#include <Helpz/settingshelper.h>
#include <Helpz/dtls_tools.h>

//--------
#include <plus/das/jwt_helper.h>

#include "rest/restful.h"

#include "dbus_handler.h"
#include "worker.h"

namespace Das {
namespace Server {
namespace WebApi {

using boost::asio::ip::udp;
namespace Z = Helpz;

Worker::Worker(QObject *parent) :
    QObject(parent)
{
    QSettings s(qApp->applicationDirPath() + QDir::separator() + qApp->applicationName() + ".conf", QSettings::NativeFormat);

    init_logging(&s);
    init_database(&s);
    init_dbus_interface(&s);
    init_jwt_helper(&s);
    init_websocket_manager(&s);
    init_web_command(&s);
    init_restful(&s);
}

Worker::~Worker()
{
    delete restful_;

    web_command_th_->quit();
    if (!web_command_th_->wait(15000))
        web_command_th_->terminate();
    delete web_command_th_;

    websock_th_->quit();
    if (!websock_th_->wait(15000))
        websock_th_->terminate();
    delete websock_th_;

    delete dbus_;
    delete dbus_handler_;
    delete db_pending_thread_;
    delete db_conn_info_;
}

void Worker::init_logging(QSettings *s)
{
    std::tuple<bool, bool> t = Helpz::SettingsHelper
        #if (__cplusplus < 201402L) || (defined(__GNUC__) && (__GNUC__ < 7))
            <Z::Param<bool>,Z::Param<bool>>
        #endif
            (
            s, "Log",
            Z::Param<bool>{"Debug", false},
            Z::Param<bool>{"Syslog", true}
    )();

    logg().set_debug(std::get<0>(t));
#ifdef Q_OS_UNIX
    logg().set_syslog(std::get<1>(t));
#endif
    QMetaObject::invokeMethod(&logg(), "init", Qt::QueuedConnection);
}

void Worker::init_database(QSettings* s)
{
    db_conn_info_ = Helpz::SettingsHelper(
                s, "Database",
                Helpz::Param{"Name", "das"},
                Helpz::Param{"User", "DasUser"},
                Helpz::Param{"Password", QString()},
                Helpz::Param{"Host", "localhost"},
                Helpz::Param{"Port", 3306},
                Helpz::Param{"Prefix", "das_"},
                Helpz::Param{"Driver", "QMYSQL"}, // QPSQL
                Helpz::Param{"ConnectOptions", QString()}
                ).ptr<Helpz::DB::Connection_Info>();

    Helpz::DB::Connection_Info::set_common(*db_conn_info_);
    db_pending_thread_ = new Helpz::DB::Thread{Helpz::DB::Connection_Info(*db_conn_info_)};
}

void Worker::init_dbus_interface(QSettings* s)
{
    dbus_handler_ = new Dbus_Handler(this);
    dbus_ = Helpz::SettingsHelper(
                s, "DBus_Interface", dbus_handler_,
                Helpz::Param{"Service", DAS_DBUS_DEFAULT_SERVICE_SERVER},
                Helpz::Param{"Object", DAS_DBUS_DEFAULT_OBJECT},
                Helpz::Param{"Interface", DAS_DBUS_DEFAULT_INTERFACE}
                ).ptr<DBus::Interface>();
}

void Worker::init_jwt_helper(QSettings* s)
{
    std::tuple<QByteArray> t = Helpz::SettingsHelper(
            s, "WebApi",
            Helpz::Param<QByteArray>{"SecretKey", QByteArray()}
    )();

    QByteArray secret_key = std::get<0>(t);
    jwt_helper_ = std::make_shared<JWT_Helper>(std::string{secret_key.constData(), static_cast<std::size_t>(secret_key.size())});
}

void Worker::init_websocket_manager(QSettings* s)
{
    websock_th_ = Websocket_Thread()(
                s, "WebSocket",
                jwt_helper_,
                Helpz::Param<quint16>{"Port", 25589},
                Helpz::Param{"CertPath", QString()},
                Helpz::Param{"KeyPath", QString()});
    websock_th_->start();
//    connect(websock_th_->ptr(), &Network::WebSocket::closed, []() {});
}

void Worker::init_web_command(QSettings* /*s*/)
{
    assert(websock_th_);
    web_command_th_ = new WebCommandThread(websock_th_->ptr());
    web_command_th_->start();
    connect(web_command_th_->ptr(), &Network::WebCommand::get_scheme_connection_state, dbus_, &DBus::Interface::get_scheme_connection_state, Qt::BlockingQueuedConnection);
    connect(web_command_th_->ptr(), &Network::WebCommand::send_message_to_scheme, dbus_, &DBus::Interface::send_message_to_scheme, Qt::QueuedConnection);
}

void Worker::init_restful(QSettings* s)
{
    Rest::Config rest_config = Helpz::SettingsHelper(
        s, "Rest",
        Helpz::Param{"Thread_Count", 3},
        Helpz::Param<std::string>{"Address", "0.0.0.0"},
        Helpz::Param<std::string>{"Port", "8123"}
    ).obj<Rest::Config>();

    restful_ = new Rest::Restful{dbus_, jwt_helper_, rest_config};
}

} // namespace WebApi
} // namespace Server
} // namespace Das
