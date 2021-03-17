#include <QtWebSockets/QWebSocket>
#include <QWebSocketCorsAuthenticator>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QThread>
#include <QSslKey>
#include <QFile>
#include <QUuid>
#include <QMutexLocker>

#include <Helpz/net_protocol.h>
#include <Helpz/settingshelper.h>
#include <Helpz/db_base.h>

#include <Das/commands.h>
#include <Das/db/scheme_group.h>
#include <plus/das/jwt_helper.h>

#define PICOJSON_USE_INT64
#include <plus/jwt-cpp/include/jwt-cpp/picojson.h>

#include "websocket.h"

#include <QRegularExpression>
#include <QBitArray>
void func(QDataStream& stream, void* data)
{

#define NS(x) QT_PREPEND_NAMESPACE(x)

    switch (0) {

    case QMetaType::QChar: // 7
        stream >> *static_cast< NS(QChar)*>(data);
        break;

    case QMetaType::QVariantMap: // 8
        stream >> *static_cast< NS(QVariantMap)*>(data);
        break;

    case QMetaType::QStringList: // 11
        stream >> *static_cast< NS(QStringList)*>(data);
        break;

    case QMetaType::QByteArray: // 12
        stream >> *static_cast< NS(QByteArray)*>(data);
        break;

    case QMetaType::QBitArray: // 13
        stream >> *static_cast< NS(QBitArray)*>(data);
        break;

    case QMetaType::QDate: // 14
        stream >> *static_cast< NS(QDate)*>(data);
        break;
    case QMetaType::QTime: // 15
        stream >> *static_cast< NS(QTime)*>(data);
        break;
    case QMetaType::QDateTime: // 16
        stream >> *static_cast< NS(QDateTime)*>(data);
        break;

    case QMetaType::QUrl: // 17
        stream >> *static_cast< NS(QUrl)*>(data);
        break;

    case QMetaType::QRegExp: // 27
        stream >> *static_cast< NS(QRegExp)*>(data);
        break;

    case QMetaType::QVariantHash: // 28
        stream >> *static_cast< NS(QVariantHash)*>(data);
        break;

    case QMetaType::QUuid: // 30
        stream >> *static_cast< NS(QUuid)*>(data);
        break;

    case QMetaType::QRegularExpression: // 44
        stream >> *static_cast< NS(QRegularExpression)*>(data);
        break;

    case QMetaType::QByteArrayList: // 49
        stream >> *static_cast< NS(QByteArrayList)*>(data);
        break;
    }
}

namespace Das {

Q_LOGGING_CATEGORY(WebSockLog, "net.web")

namespace Net {

using namespace Helpz::DB;

Websocket_Client::Websocket_Client() :
    id_(0), auth_sended_time_(QDateTime::currentMSecsSinceEpoch())
{
}

// --------------------------------------------------------------------------------

bool WebSocket::Stream_Item::operator<(const WebSocket::Stream_Item &o) const
{
    return scheme_id_ < o.scheme_id_
            || (scheme_id_ == o.scheme_id_ && dev_item_id_ < o.dev_item_id_);
}

// --------------------------------------------------------------------------------

WebSocket::WebSocket(std::shared_ptr<JWT_Helper> jwt_helper, const QString& address, quint16 port,
                     const QString& certFilePath, const QString& keyFilePath, QObject *parent) :
    QObject(parent),
    server_(new QWebSocketServer(QStringLiteral("Device Access Control"),
                                            certFilePath.isEmpty() || keyFilePath.isEmpty() ? QWebSocketServer::NonSecureMode : QWebSocketServer::SecureMode, this)),
    jwt_helper_(std::move(jwt_helper))
{
    if (!certFilePath.isEmpty() && !certFilePath.isEmpty())
    {
        QSslConfiguration sslConfiguration;
        QFile certFile(certFilePath), keyFile(keyFilePath);
        certFile.open(QIODevice::ReadOnly);
        keyFile.open(QIODevice::ReadOnly);
        QSslCertificate certificate(&certFile, QSsl::Pem);
        QSslKey sslKey(&keyFile, QSsl::Rsa, QSsl::Pem);
        certFile.close();
        keyFile.close();
        sslConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);
        sslConfiguration.setLocalCertificate(certificate);
        sslConfiguration.setPrivateKey(sslKey);
        sslConfiguration.setProtocol(QSsl::TlsV1SslV3);
        server_->setSslConfiguration(sslConfiguration);
    }

    qRegisterMetaType<uint32_t>("uint32_t");
    qRegisterMetaType<Scheme_Info>("Scheme_Info");
    qRegisterMetaType<QTimeZone>("QTimeZone");
    qRegisterMetaType<QVector<DIG_Param_Value>>("QVector<DIG_Param_Value>");
    qRegisterMetaType<std::shared_ptr<Net::Websocket_Client>>("std::shared_ptr<Net::Websocket_Client>");

    connect(server_, &QWebSocketServer::originAuthenticationRequired, this, &WebSocket::originAuthentication);
    connect(server_, &QWebSocketServer::newConnection, this, &WebSocket::onNewConnection);
    connect(server_, &QWebSocketServer::sslErrors, this, &WebSocket::onSslErrors);
    connect(server_, &QWebSocketServer::closed, this, &WebSocket::closed);
    connect(server_, &QWebSocketServer::acceptError, this, &WebSocket::acceptError);
    connect(server_, &QWebSocketServer::serverError, this, &WebSocket::serverError);

//    while ((!worker->n_mng_th && (QThread::msleep(5), true)) ||
//           (!worker->n_mng_th->ptr() && !worker->n_mng_th->wait(5)));
//    connect(worker->n_mng_th->ptr(), &Manager::devItemsChanged,
//            this, &WebSocket::sendDevice_ItemValues, Qt::QueuedConnection);
//    connect(worker->n_mng_th->ptr(), &Manager::connectStateChanged,
//            this, &WebSocket::sendConnectState, Qt::QueuedConnection);
//    connect(worker->n_mng_th->ptr(), &Manager::eventlog,
//            this, &WebSocket::sendEventMessage, Qt::QueuedConnection);
//    connect(worker->n_mng_th->ptr(), &Manager::modeChanged,
//            this, &WebSocket::sendModeChanged, Qt::QueuedConnection);

    const QHostAddress host_address((!address.isEmpty()) ? QHostAddress(address) : QHostAddress::Any);
    if (server_->listen(host_address, port))
        qCDebug(WebSockLog) << "WebSocket listening on port" << port << "url:" << server_->serverUrl().toString();
    else
        qCCritical(WebSockLog) << server_->errorString();
}

WebSocket::~WebSocket()
{
    server_->close();
//    for (auto&& client: m_clients)
//        delete client.sock;
    qDeleteAll(client_map_.keys());
//    qDeleteAll(m_clients);
}

void WebSocket::originAuthentication(QWebSocketCorsAuthenticator *pAuthenticator)
{
    qCritical() << "originAuthenticationRequired" << pAuthenticator->origin()
                << "allowed" << pAuthenticator->allowed();
}

void WebSocket::acceptError(QAbstractSocket::SocketError socketError)
{
    qCritical() << "acceptError" << socketError;
}

void WebSocket::serverError(QWebSocketProtocol::CloseCode closeCode)
{
    qCritical() << "serverError" << closeCode;
}

void WebSocket::onNewConnection()
{
    QWebSocket *socket = server_->nextPendingConnection();
//    socket->moveToThread();
    connect(socket, &QWebSocket::binaryMessageReceived, this, &WebSocket::processBinaryMessage);
    connect(socket, &QWebSocket::disconnected, this, &WebSocket::socketDisconnected);

    QMutexLocker lock(&clients_mutex_);
    client_map_.insert(socket, std::make_shared<Websocket_Client>());
    socket->sendBinaryMessage(QByteArray(1, WS_AUTH));
}

void WebSocket::processBinaryMessage(const QByteArray& message)
{
    // qCDebug(WebSockLog) << "Binary Message received:" << message.size() << message.left(16).toHex();

    QWebSocket *socket = qobject_cast<QWebSocket *>(sender());
    if (!socket) return;

    auto it = client_map_.find(socket);
    if (it == client_map_.cend() || !it.value()) return;
    Websocket_Client& client = *it.value();

    QDataStream ds(message);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);

    quint8 cmd;
    uint32_t scheme_id;
    ds >> cmd >> scheme_id;

    if (scheme_id && client.last_scheme_id_queried_ != scheme_id)
        client.last_scheme_id_queried_ = scheme_id;
//    qDebug(WebSockLog) << pClient->peerAddress().toString() << pClient->peerPort() << "CMD:" << (WebSockCmd)cmd << "SCHEME" << scheme_id << "MSG" << message.size();

    if (cmd == WS_AUTH)
    {
        if (client.id_ == 0)
        {
            QByteArray token;
            ds >> token;

            if (auth(token, client))
            {
                socket->sendBinaryMessage(QByteArray(1, WS_WELCOME));
                return;
            }
            socket->close(QWebSocketProtocol::CloseCodeNormal, "Bad token");

                /*
            if (user.contains("user"))
            {
                it->isAuthenticated = true;
                it->isStaff = user["is_staff"].toBool();
                it->scheme_group_id = user["scheme_group"].toUInt();
                QJsonArray groups = user["groups"].toArray();
                for (const QJsonValue& group: groups)
                {
                    it->group_id = group.toObject()["id"].toUInt();
                    break;
                }

                pClient->sendBinaryMessage(QByteArray(1, wsWelcome));
                qCDebug(WebSockLog) << "Authenticated user:" << user["user"].toString();
                return;
            }

            qCWarning(WebSockLog) << "Bad auth token cmd:" << (int)cmd << user["error"] << django_res;
            pClient->close(QWebSocketProtocol::CloseCodeNormal, "Bad token");
            */
        }
        return;
    }
    else if (client.id_ == 0)
    {
        qCDebug(WebSockLog) << "Unathorized detected";
        socket->sendBinaryMessage(QByteArray(1, WS_AUTH));
    }
    else if (cmd < WEB_SOCK_CMD_COUNT)
    {
//        qint64 pos = ds.device()->pos();

        if (cmd == WS_STREAM_TOGGLE)
        {
            qint64 pos = ds.device()->pos();
            try
            {
                if (!Helpz::apply_parse(ds, &WebSocket::stream_toggle, this, socket, scheme_id))
                    return;
            }
            catch(...)
            {
                return;
            }
            ds.device()->seek(pos);
        }

        if (ds.device()->bytesAvailable() < 200000000) // 200mb
        {
            emit through_command(it.value(), scheme_id, cmd, ds.device()->readAll());
        }
//        ds.device()->seek(pos);
    }
    else
        std::cerr << client.id_ << ' ' << scheme_id << " Unknown WebSocket Message: " << (uint32_t)cmd << std::endl;
    /*return;

    std::shared_ptr<scheme::base> scheme = get_scheme_in_scheme_group_by_id(it->scheme_group_id, scheme_id).value_or(nullptr);

    if (cmd == ConnectInfo) {
        QByteArray msg;

        if (scheme)
        {
            QString ip;
            ip = QString::fromStdString(scheme->address());
            msg = prepare_connect_state_message(scheme_id, ip, scheme->time().zone, scheme->time().offset);
        }
        else
            msg = prepare_connect_state_message(scheme_id);

        pClient->sendBinaryMessage(msg);
        return;
    }

    if (!scheme)
        return;

    try {
        switch (cmd) {
        case WriteToDevItem: Helpz::applyParse(&scheme::base::send_value, scheme.get(), ds); break;
        case ChangeGroupMode: Helpz::applyParse(&scheme::base::send_mode, scheme.get(), ds); break;
        case ChangeParamValues: Helpz::applyParse(&scheme::base::send_param_values, scheme.get(), ds); break;
        case ChangeCode: Helpz::applyParse(&scheme::base::send_code, scheme.get(), ds); break;
        case ExecScript: Helpz::applyParse(&scheme::base::send_script, scheme.get(), ds); break;
        case Restart: scheme->send_restart(); break;

        default:
            std::cerr << scheme->title() << " Unknown WebSocket Message: " << (int)cmd << std::endl;
    //        pClient->sendBinaryMessage(message);
            break;
        }
    } catch(const std::exception& e) {
        qCCritical(WebSockLog) << "EXCEPTION: processBinaryMessage" << (int)cmd << e.what();
    }*/
}

void WebSocket::onSslErrors(const QList<QSslError> &errors)
{
    qCDebug(WebSockLog) << "SslError" << errors;
}

void WebSocket::socketDisconnected()
{
    QWebSocket *socket = qobject_cast<QWebSocket *>(sender());
    if (socket)
    {
//    qCDebug(WebSockLog) << "socketDisconnected:" << pClient->peerAddress().toString() << pClient->peerPort();

        QMutexLocker lock(&clients_mutex_);

        auto it = client_map_.find(socket);
        uint32_t user_id = it != client_map_.end() && *it ? it->get()->id_ : 0;

        for (auto cl_it = client_uses_stream_.begin(); cl_it != client_uses_stream_.end();)
        {
            std::set<QWebSocket*>& clients = cl_it->second;

            clients.erase(socket);
            if (clients.empty())
            {
                emit stream_stoped(cl_it->first.scheme_id_, cl_it->first.dev_item_id_);

                stream_stop(cl_it->first.scheme_id_, cl_it->first.dev_item_id_, user_id);
                cl_it = client_uses_stream_.erase(cl_it);
            }
            else
                ++cl_it;
        }

        client_map_.erase(it);
        socket->deleteLater();
    }
}

template<typename T>
void WebSocket::send_log_data(const Scheme_Info &scheme, uint8_t cmd, const QVector<T> &data,
                              std::function<bool(QDataStream&, const T&)> func)
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);

    ds << cmd << scheme.id() << (uint32_t)data.size();

    const qint64 old_time = QDateTime::currentDateTimeUtc().addSecs(10 * 60 * -1).toMSecsSinceEpoch();

    int size = 0;
    for (const T& item: data)
        if (item.timestamp_msecs() > old_time && (!func || func(ds, item)))
        {
            if (!func)
                ds << item;
            ++size;
        }

    if (size != data.size())
    {
        if (!size)
            return;

        ds.device()->seek(1 + 4); // uint8_t + uint32_t
        ds << size;
    }
    send(scheme, message);
}

bool WebSocket::auth(const QByteArray& token, Websocket_Client& client)
{
    try
    {
        const std::string payload = jwt_helper_->decode_and_verify(token.toStdString());

        picojson::value json_value;
        const std::string err = picojson::parse(json_value, payload);
        if (!err.empty())
            throw std::runtime_error("JSON parse error: " + err);

        if (json_value.is<picojson::object>())
        {
            const picojson::object obj = json_value.get<picojson::object>();
//            std::cout << "user_id: " << obj.at("user_id").to_str() << std::endl;
            client.id_ = obj.at("user_id").get<int64_t>();

            using T = DB::Scheme_Group_User;
            Table table = db_table<T>();
            const QString where = "WHERE " + table.field_names().at(T::COL_user_id) + "=?";
            table.field_names() = QStringList{table.field_names().at(T::COL_group_id)};

            Base& db = Base::get_thread_local_instance();
            QSqlQuery q = db.select(table, where, {client.id_});
            while (q.next())
            {
                client.scheme_group_id_set_.insert(q.value(0).toUInt());
            }

            if (client.scheme_group_id_set_.empty())
                client.id_ = 0;
            return client.id_;
        }
        throw std::runtime_error("Bad payload");
    }
    catch(const std::exception& e)
    {
        qCDebug(WebSockLog) << "Token error:" << e.what();
    }
    catch(...)
    {
        qCDebug(WebSockLog) << "Token error unknown.";
    }

    return false;
}

bool WebSocket::stream_toggle(uint32_t dev_item_id, bool state, QWebSocket *socket, uint32_t scheme_id)
{
    const Stream_Item stream_item{scheme_id, dev_item_id};
    std::set<QWebSocket*>& clients = client_uses_stream_[stream_item];

    if (state)
    {
        clients.insert(socket);
        return clients.size() == 1;
    }
    else
    {
        clients.erase(socket);
        if (!clients.empty())
            return false;

        emit stream_stoped(stream_item.scheme_id_, stream_item.dev_item_id_);
        client_uses_stream_.erase(stream_item);
    }
    return true;
}

void WebSocket::stream_stop(uint32_t scheme_id, uint32_t dev_item_id, uint32_t user_id)
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << dev_item_id << false;

    std::shared_ptr<Websocket_Client> client = std::make_shared<Websocket_Client>();
    client->id_ = user_id;

    emit through_command(client, scheme_id, WS_STREAM_TOGGLE, message);
}

void WebSocket::sendDevice_ItemValues(const Scheme_Info &scheme, const QVector<Log_Value_Item> &pack)
{
    std::function<bool(QDataStream&, const Log_Value_Item&)> func = [](QDataStream& ds, const Log_Value_Item& item)
    {
        if (item.is_big_value())
            return false;
        ds << item.item_id() << item.raw_value() << item.value();
        return true;
    };
    send_log_data(scheme, WS_DEV_ITEM_VALUES, pack, func);
}

void WebSocket::send_dig_mode_pack(const Scheme_Info &scheme, const QVector<DIG_Mode> &pack)
{
    std::function<bool(QDataStream&, const DIG_Mode&)> func = [this, &scheme](QDataStream& ds, const DIG_Mode& item)
    {
        Q_UNUSED(ds);
        sendModeChanged(scheme, item);
        return false; // TODO: Фронт должен принимать массив
    };
    send_log_data(scheme, WS_DIG_MODE, pack, func);
}

void WebSocket::sendModeChanged(const Scheme_Info &scheme, const DIG_Mode &mode)
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_DIG_MODE << scheme.id() << mode.mode_id() << mode.group_id();
    send(scheme, message);
}

void WebSocket::send_dig_param_values_changed(const Scheme_Info &scheme, const QVector<DIG_Param_Value> &pack)
{
    send_log_data(scheme, WS_CHANGE_DIG_PARAM_VALUES, pack);
}

void WebSocket::send_connection_state(const Scheme_Info &scheme, uint8_t connection_state)
{
    QByteArray msg = prepare_connection_state_message(scheme.id(), connection_state);
    send(scheme, msg);
}

void WebSocket::sendEventMessage(const Scheme_Info& scheme, const QVector<Log_Event_Item>& event_pack)
{
    send_log_data(scheme, WS_EVENT_LOG, event_pack);
}

void WebSocket::send_dig_status_changed(const Scheme_Info &scheme, const QVector<DIG_Status> &pack)
{
    std::function<bool(QDataStream&, const DIG_Status&)> func = [this, &scheme](QDataStream& ds, const DIG_Status& item)
    {
        Q_UNUSED(ds);
        send_dig_status(scheme, item);
        return false; // TODO: Фронт должен принимать массив
    };
    send_log_data(scheme, WS_GROUP_STATUS_ADDED, pack, func);
}

void WebSocket::send_dig_status(const Scheme_Info &scheme, const DIG_Status &status)
{
    const uint8_t cmd = status.is_removed() ? WS_GROUP_STATUS_REMOVED : WS_GROUP_STATUS_ADDED;

    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << cmd << scheme.id() << status.group_id() << status.status_id();
    if (!status.is_removed())
        ds << status.args();

    send(scheme, message);
}

void WebSocket::send_structure_changed(const Scheme_Info &scheme, const QByteArray &data)
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_STRUCT_MODIFY << scheme.id();
    ds.writeBytes(data.constBegin(), data.size());
    send(scheme, message);
}

void WebSocket::send_time_info(const Scheme_Info& scheme, const QTimeZone& tz, qint64 time_offset)
{
    QDateTime dt = QDateTime::currentDateTime();
    dt = dt.addMSecs(time_offset);

    QString zone_name;
    if (tz.isValid())
    {
//            zone_name = tz.displayName(QTimeZone::GenericTime);
        zone_name = tz.id().constData();
        dt = dt.toTimeZone(tz);
    }

    qint64 time = dt.toMSecsSinceEpoch();

    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_TIME_INFO << scheme.id() << time << zone_name;
    send(scheme, message);
}

void WebSocket::send_ip_address(const Scheme_Info& scheme, const QString& ip_address)
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_IP_ADDRESS << scheme.id() << ip_address;
    send(scheme, message);
}

void WebSocket::send_stream_toggled(const Scheme_Info &scheme, uint32_t user_id, uint32_t dev_item_id, bool state)
{
    const Stream_Item stream_item{scheme.id(), dev_item_id};
    auto it = client_uses_stream_.find(stream_item);
    if (it == client_uses_stream_.cend())
    {
        if (state)
            stream_stop(scheme.id(), dev_item_id, user_id);
        return;
    }

    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_STREAM_TOGGLE << scheme.id() << user_id << dev_item_id << state;

    for (QWebSocket* sock: it->second)
        sock->sendBinaryMessage(message);

    if (!state)
    {
        emit stream_stoped(stream_item.scheme_id_, stream_item.dev_item_id_);
        client_uses_stream_.erase(it);
    }
}

void WebSocket::send_stream_data(const Scheme_Info &scheme, uint32_t dev_item_id, const QByteArray &data)
{
    send_stream_id_data(scheme.id(), dev_item_id, data);
}

void WebSocket::send_stream_id_data(uint32_t scheme_id, uint32_t dev_item_id, const QByteArray &data)
{
    const Stream_Item stream_item{scheme_id, dev_item_id};
    auto it = client_uses_stream_.find(stream_item);
    if (it == client_uses_stream_.cend())
    {
        stream_stop(scheme_id, dev_item_id);
        return;
    }

    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_STREAM_DATA << scheme_id << dev_item_id;
    ds.writeRawData(data.constData(), data.size());

    for (QWebSocket* sock: it->second)
        sock->sendBinaryMessage(message);
}

void WebSocket::send_stream_id_text(uint32_t scheme_id, uint32_t dev_item_id, const QString &text)
{
    const Stream_Item stream_item{scheme_id, dev_item_id};
    auto it = client_uses_stream_.find(stream_item);
    if (it == client_uses_stream_.cend())
    {
        stream_stop(scheme_id, dev_item_id);
        return;
    }

    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_STREAM_TEXT << scheme_id << dev_item_id << text;

    for (QWebSocket* sock: it->second)
        sock->sendBinaryMessage(message);
}

QByteArray WebSocket::prepare_connection_state_message(uint32_t scheme_id, uint8_t connection_state) const
{
    QByteArray message;
    QDataStream ds(&message, QIODevice::WriteOnly);
    ds.setVersion(Helpz::Net::Protocol::DATASTREAM_VERSION);
    ds << (quint8)WS_CONNECTION_STATE << scheme_id << connection_state;
    return message;
}

void WebSocket::send(const Scheme_Info &scheme, const QByteArray &data) const
{
    QMutexLocker lock(&clients_mutex_);

    qint64 curr_time = QDateTime::currentMSecsSinceEpoch();

    for (auto it = client_map_.cbegin(); it != client_map_.cend(); ++it)
    {
        if (it.value()->id_ == 0)
        {
            if ((curr_time - it.value()->auth_sended_time_) >= 500)
            {
                it.value()->auth_sended_time_ = curr_time;
                it.key()->sendBinaryMessage(QByteArray(1, WS_AUTH));
            }
        }
        else if (scheme.id() == 0 || (it.value()->last_scheme_id_queried_ == scheme.id()
                                      && scheme.check_scheme_groups(it.value()->scheme_group_id_set_)))
        {
            it.key()->sendBinaryMessage(data);
        }
    }
}

void WebSocket::send_to_client(std::shared_ptr<Websocket_Client> client, const QByteArray& data) const
{
    QMutexLocker lock(&clients_mutex_);

    for (auto it = client_map_.cbegin(); it != client_map_.cend(); ++it)
    {
        if (it.value() == client)
        {
            it.key()->sendBinaryMessage(data);
            return;
        }
    }
}

} // namespace Net
} // namespace Das
