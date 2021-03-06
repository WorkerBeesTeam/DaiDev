#ifndef DAS_DB_BASE_TYPE_H
#define DAS_DB_BASE_TYPE_H

#include <QVector>
#include <QString>
#include <QDataStream>

#include <Das/daslib_global.h>
#include <Das/db/schemed_model.h>

namespace Das {
namespace DB {

struct DAS_LIBRARY_SHARED_EXPORT Base_Type : public Schemed_Model
{
    Base_Type(uint32_t id = 0, const QString& name = QString(), uint32_t scheme_id = Schemed_Model::default_scheme_id());
    Base_Type(Base_Type&& other) = default;
    Base_Type(const Base_Type& other) = default;
    Base_Type& operator=(Base_Type&& other) = default;
    Base_Type& operator=(const Base_Type& other) = default;

    uint32_t id() const;
    void set_id(uint32_t id);

    QString name() const;
    void set_name(const QString& name);

private:
    uint32_t id_;
    QString name_;

    friend QDataStream &operator>>(QDataStream &ds, Base_Type& item);
};

QDataStream &operator>>(QDataStream &ds, Base_Type& item);
QDataStream &operator<<(QDataStream &ds, const Base_Type& item);

template<class T>
class Base_Type_Manager
{
public:
    using Type_List = QVector<T>;

    void add(const T& type)
    {
        types_.push_back(type);
    }

    template<typename... Args>
    void add(Args... args)
    {
        types_.push_back(T{args...});
    }

    QString name(uint type_id) const
    {
        return type(type_id).name();
    }

    void set_name(uint type_id, const QString& str)
    {
        get_or_add(type_id)->set_name(str);
    }

    T* get_type(uint type_id)
    {
        for (auto& type: types_)
            if (type.id() == type_id)
                return &type;
        return &empty_;
    }

    T* get_type(const QString& name)
    {
        for (auto& type: types_)
            if (type.name() == name)
                return &type;
        return &empty_;
    }

    const T& type(uint type_id) const
    {
        for (auto& type: types_)
            if (type.id() == type_id)
                return type;
        return empty_;
    }

    void set(const Type_List& list) { types_ = list; }
    Type_List* get_types() { return &types_; }
    const Type_List& types() const { return types_; }

    void clear() { types_.clear(); }
protected:
    T* get_or_add(uint32_t type_id)
    {
        for (auto& type: types_)
            if (type.id() == type_id)
                return &type;

        T new_obj;
        new_obj.set_id(type_id);

        return &(*types_.insert(types_.end(), std::move(new_obj)));
    }

    Type_List types_;

//    template <typename U> friend QDataStream &operator>> (QDataStream &ds, BaseTypeManager<U> &type);
    friend QDataStream &operator>>(QDataStream &ds, Base_Type_Manager<T> &type) {
        return ds >> type.types_;
    }
private:
    T empty_;
};

struct DAS_LIBRARY_SHARED_EXPORT Titled_Type : public Base_Type {
    Titled_Type(uint id = 0, const QString& name = QString(), const QString& title = QString());
    Titled_Type(Titled_Type&& o) = default;
    Titled_Type(const Titled_Type& o) = default;
    Titled_Type& operator=(Titled_Type&& o) = default;
    Titled_Type& operator=(const Titled_Type& o) = default;

    QString title() const;
    void set_title(const QString& title);
private:
    QString title_;

    friend QDataStream &operator>>(QDataStream &ds, Titled_Type& item);
};

QDataStream &operator>>(QDataStream &ds, Titled_Type& item);
QDataStream &operator<<(QDataStream &ds, const Titled_Type& item);

template<class T>
struct Titled_Type_Manager : public Base_Type_Manager<T>
{
    QString title(uint type_id) const
    {
        return Base_Type_Manager<T>::type(type_id).title();
    }

    void set_title(uint type_id, const QString& str)
    {
        Base_Type_Manager<T>::getOrAdd(type_id)->set_title(str);
    }
};

//template <typename Container>
//QDataStream &writeSequentialContainer(QDataStream &s, const Container &c)
//{
//    s << uint32_t(c.size());
//    for (const typename Container::value_type &t : c)
//        s << t;

//    return s;
//}

template <typename T>
inline QDataStream &operator<<(QDataStream &ds, const Base_Type_Manager<T> &type)
{
    return ds << type.types();
//    return writeSequentialContainer(s, type.types());
}

//template <typename T>
//inline QDataStream &operator>>(QDataStream &ds, BaseTypeManager<T> &type)
//{
//    return ds >> type.types_;
//}

} // namespace DB
} // namespace Das

#endif // DAS_DB_BASE_TYPE_H
