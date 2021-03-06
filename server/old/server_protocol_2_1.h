#ifndef DAS_SERVER_PROTOCOL_2_1_H
#define DAS_SERVER_PROTOCOL_2_1_H

#include <plus/das/authentication_info.h>

#include "log_synchronizer_2_1.h"
#include "structure_synchronizer_2_1.h"
#include "server_protocol.h"

namespace Das {
namespace Ver_2_1 {
namespace Server {

using namespace Das::Server;

class Protocol final : public Protocol_Base
{
public:
    Protocol(Work_Object* work_object);
    ~Protocol();

    Structure_Synchronizer* structure_sync();

    int protocol_version() const override;
    void send_file(uint32_t user_id, uint32_t dev_item_id, const QString& file_name, const QString& file_path) override;

    void synchronize(bool full = false) override;
private:
    void before_remove_copy() override;
    void lost_msg_detected(uint8_t msg_id, uint8_t expected) override;
    void ready_write() override;
    void process_message(uint8_t msg_id, uint8_t cmd, QIODevice &data_dev) override;
    void process_answer_message(uint8_t msg_id, uint8_t cmd, QIODevice& data_dev) override;
    void process_unauthorized_message(uint8_t msg_id, uint8_t cmd, QIODevice &data_dev);

    void auth(const Authentication_Info& info, bool modified, uint8_t msg_id);
    QString concat_version(quint8 v_major, quint8 v_minor, uint32_t v_build);
    void print_version(QIODevice &data_dev);
    void set_time_offset(const QDateTime& scheme_time, const QTimeZone &timeZone);

    void mode_changed(uint32_t user_id, uint32_t mode_id, uint32_t group_id);
    void status_added(uint32_t group_id, uint32_t info_id, const QStringList& args);
    void status_removed(uint32_t group_id, uint32_t info_id);
    void dig_param_values_changed(uint32_t user_id, const QVector<DIG_Param_Value> &pack);

    bool is_copy_;
    Log_Synchronizer log_sync_;
    Structure_Synchronizer structure_sync_;
};

} // namespace Server
} // namespace Ver_2_1
} // namespace Das

#endif // DAS_SERVER_PROTOCOL_2_1_H
