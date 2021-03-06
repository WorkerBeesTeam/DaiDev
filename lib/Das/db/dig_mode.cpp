#include "dig_mode.h"

namespace Das {
namespace DB {

DIG_Mode::DIG_Mode(qint64 timestamp_msecs, uint32_t user_id, uint32_t group_id, uint32_t mode_id) :
    Log_Base_Item(0, timestamp_msecs, user_id),
    group_id_(group_id), mode_id_(mode_id)
{
}

uint32_t DIG_Mode::group_id() const { return group_id_; }
void DIG_Mode::set_group_id(uint32_t group_id) { group_id_ = group_id; }

uint32_t DIG_Mode::mode_id() const { return mode_id_; }
void DIG_Mode::set_mode_id(uint32_t mode_id) { mode_id_ = mode_id; }

QDataStream &operator>>(QDataStream &ds, DIG_Mode &item)
{
    return ds >> static_cast<Log_Base_Item&>(item) >> item.group_id_ >> item.mode_id_;
}

QDataStream &operator<<(QDataStream &ds, const DIG_Mode &item)
{
    return ds << static_cast<const Log_Base_Item&>(item) << item.group_id() << item.mode_id();
}

} // namespace DB
} // namespace Das
