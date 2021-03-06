#ifndef DAS_LOG_SENDER_H
#define DAS_LOG_SENDER_H

#include <thread>
#include <mutex>
#include <condition_variable>

#include <Das/log/log_type.h>
#include <Das/log/log_pack.h>

#include <Database/db_log_helper.h>
#include "client_protocol.h"

namespace Das {
namespace Ver {
namespace Client {

using namespace Das::Client;

class Log_Sender
{
public:
    explicit Log_Sender(Protocol_Base* protocol);

    void send_data(Log_Type_Wrapper log_type, uint8_t msg_id);
private:

    template<typename T>
    void send_log_data(const Log_Type_Wrapper& log_type);

    template<typename T>
    void send_log_data(const Log_Type_Wrapper& log_type, std::shared_ptr<QVector<T>> log_data);

    int request_data_size_;
    Protocol_Base* protocol_;
};

} // namespace Client
} // namespace Ver
} // namespace Das

#endif // DAS_LOG_SENDER_H
