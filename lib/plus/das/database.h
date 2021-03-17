#ifndef DAS_DATABASE_HELPER_H
#define DAS_DATABASE_HELPER_H

#include <exception>
#include <functional>
#include <mutex>

#include <QBitArray>

#include <Helpz/db_base.h>
#include <Helpz/db_delete_row.h>

#include <Das/section.h>
#include <Das/log/log_pack.h>
#include <Das/type_managers.h>

namespace Das {
namespace DB {

class Helper : public QObject, public Helpz::DB::Base
{
    Q_OBJECT
public:
    Helper(QObject* parent = nullptr);
    Helper(const Helpz::DB::Connection_Info &info, const QString& name = QSqlDatabase::defaultConnection, QObject* parent = nullptr);

    static QString get_default_suffix(const QString &table_short_name = QString());
    static QString get_default_where_suffix(const QString &table_short_name = QString());
    static QVector<Save_Timer> get_save_timer_vect();
    static QVector<Code_Item> get_code_item_vect();
    static bool set_mode(const DIG_Mode& mode);

    void fill_types(Type_Managers *type_mng);

    void fill_devices(Scheme *scheme, std::map<uint32_t, Device_item_Group*> groups);
    void fill_section(Scheme *scheme, std::map<uint32_t, Device_item_Group *> *groups = nullptr);

    void init_scheme(Scheme* scheme, bool typesAlreadyFilled = false);

    static bool check_permission(uint32_t user_id, const std::string& permission);
    static bool is_admin(uint32_t user_id);

    static bool compare_passhash(const std::string &password, const std::string &hash_data) noexcept(false);
private:
};

} // namespace DB
} // namespace Das

#endif // DAS_DATABASE_H
