#ifndef DAS_REST_JSON_HELPER_H
#define DAS_REST_JSON_HELPER_H

#define PICOJSON_USE_INT64
#include <picojson/picojson.h>

#include <QDateTime>

#include <Helpz/db_builder.h>

namespace Das {
namespace Rest {

template<typename T, typename... Args>
void set_variant_from_json_value(QVariant& value, const picojson::value& json_value)
{
    if (json_value.is<T>())
    {
        if constexpr (std::is_same<std::string, T>::value)
        {
            const QString str_value = QString::fromStdString(json_value.get<std::string>());
            if (str_value.isEmpty())
                value = QString("");
            else if (str_value.front() >= '1' && str_value.front() <= '2')
            {
                const QDateTime date_val = QDateTime::fromString(str_value, Qt::ISODateWithMs);
                if (date_val.isValid())
                    value = date_val;
                else
                    value = str_value;
            }
            else
                value = str_value;
        }
        else
            value = json_value.get<T>();
    }
    else
    {
        if constexpr (sizeof...(Args))
            set_variant_from_json_value<Args...>(value, json_value);
        else
            value.clear();
    }
}

template<typename T>
T from_json(const picojson::object& obj)
{
    const QStringList names = T::table_column_names();
    int index;
    QVariant value;
    T item;

    for (auto it: obj)
    {
        index = names.indexOf(QString::fromStdString(it.first));
        if (index == -1)
            continue;

        set_variant_from_json_value<bool, double, std::string>(value, it.second);
        T::value_setter(item, index, value);
    }

    return item;
}

// stoa_or - Example: auto dig = stoa_or(std::stoul, str, 1000000UL)
template<typename T = unsigned long>
T stoa_or(const std::string& text, T default_value = static_cast<T>(0), T(*func)(const std::string&, size_t*, int) = std::stoul)
{
    try {
        return func(text, 0, 10);
    } catch(...) {}
    return default_value;
}


inline picojson::value pico_from_qvariant(const QVariant& value)
{
    switch (value.type())
    {
    case QVariant::Invalid: return picojson::value{};
    case QVariant::Bool: return picojson::value{value.toBool()};
    case QVariant::Double: return picojson::value{value.toDouble()};
    case QVariant::Int:
    case QVariant::UInt:
    case QVariant::LongLong:
    case QVariant::ULongLong: return picojson::value{value.value<int64_t>()};

    case QVariant::StringList:
    case QVariant::List:
    {
        picojson::array arr;
        QList<QVariant> value_list = value.toList();
        for (const QVariant& elem: value_list)
            arr.push_back(pico_from_qvariant(elem));
        return picojson::value{arr};
    }

    case QVariant::Map:
    {
        picojson::object obj;
        QMap<QString, QVariant> value_obj = value.toMap();
        for (auto it = value_obj.cbegin(); it != value_obj.cend(); ++it)
            obj.emplace(it.key().toStdString(), pico_from_qvariant(it.value()));
        return picojson::value{obj};
    }

    case QVariant::String:
    case QVariant::ByteArray:
    default:
        return picojson::value{value.toString().toStdString()};
    }
}

inline QVariant pico_to_qvariant(const picojson::value& value)
{
    if (value.is<bool>())
        return value.get<bool>();
    else if (value.is<int64_t>())
        return QVariant::fromValue(value.get<int64_t>());
    else if (value.is<double>())
        return value.get<double>();
    else if (value.is<std::string>())
        return QString::fromStdString(value.get<std::string>());
    return {};
}

template<typename T>
T obj_from_pico(const picojson::object& item, const Helpz::DB::Table& table)
{
    T obj;

    int i;
    for (const auto& it: item)
    {
        i = table.field_names().indexOf(QString::fromStdString(it.first));
        if (i < 0 || i >= table.field_names().size())
            throw std::runtime_error("Unknown property: " + it.first);
        T::value_setter(obj, i, pico_to_qvariant(it.second));
    }

    return obj;
}

template<typename T>
T obj_from_pico(const picojson::object& item)
{
    const auto table = Helpz::DB::db_table<T>();
    return obj_from_pico<T>(item, table);
}

template<typename T>
T obj_from_pico(const picojson::value& value, const Helpz::DB::Table& table)
{
    if (!value.is<picojson::object>())
        throw std::runtime_error("Is not an object");
    return obj_from_pico<T>(value.get<picojson::object>(), table);
}

template<typename T>
T obj_from_pico(const picojson::value& value)
{
    const auto table = Helpz::DB::db_table<T>();
    return obj_from_pico<T>(value, table);
}

template<typename T>
picojson::object obj_to_pico(const T& item, const QStringList& names)
{
    picojson::object obj;
    for (int i = 0; i < T::COL_COUNT; ++i)
        obj.emplace(names.at(i).toStdString(), pico_from_qvariant(T::value_getter(item, i)));
    return obj;
}

template<typename T>
picojson::object gen_json_object(const QSqlQuery& query, const QStringList& names)
{
    if (query.record().count() < T::COL_COUNT)
        return {};
    const T item = Helpz::DB::db_build<T>(query);
    return obj_to_pico(item, names);
}

template<typename T>
picojson::object gen_json_object(const QSqlQuery& query)
{
    const QStringList names = T::table_column_names();
    return gen_json_object<T>(query, names);
}

template<typename T>
picojson::array gen_json_array(const QString& suffix = QString(), const QVariantList& values = QVariantList())
{
    Helpz::DB::Base& db = Helpz::DB::Base::get_thread_local_instance();
    QStringList names = T::table_column_names();
    picojson::array json_array;
    auto q = db.select(Helpz::DB::db_table<T>(), suffix, values);
    while (q.next())
        json_array.emplace_back(gen_json_object<T>(q, names));

    return json_array;
}

template<typename T>
std::string gen_json_list(const QString& suffix = QString(), const QVariantList& values = QVariantList())
{
    return picojson::value(gen_json_array<T>(suffix, values)).serialize();
}

} // namespace Rest
} // namespace Das

#endif // DAS_REST_JSON_HELPER_H
