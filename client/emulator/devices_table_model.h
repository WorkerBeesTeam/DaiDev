#ifndef DEVICETABLEMODEL_H
#define DEVICETABLEMODEL_H

#include <QAbstractTableModel>
#include <QVector>
#include <QModbusServer>
#include <QModbusDataUnit>

#include <Das/device.h>
#include "registers_vector_item.h"
#include "device_table_item.h"

class DevicesTableModel : public QAbstractItemModel
{
    Q_OBJECT

    typedef std::vector<Das::Device_Item*> Device_Items_Vector;
    typedef QVector<Das::Device*> Devices_Vector;

    QVector<DeviceTableItem*> modbus_devices_vector_;
    Das::DB::Device_Item_Type_Manager* device_item_type_manager_;

    void add_items(const Devices_Vector* devices, QModbusServer* modbus_server);

    int get_real_row(int row) const;
    int row_count() const;
public slots:
    void child_item_changed(DeviceTableItem* child_item);
signals:
    void call_script(Das::Device*);
public:
    DevicesTableModel(Das::DB::Device_Item_Type_Manager* mng, const QVector<Das::Device *> *devices_vector, QModbusServer *modbus_server, QObject *parent = nullptr);
    DevicesTableModel(Das::DB::Device_Item_Type_Manager* mng, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &child = QModelIndex()) const override;

    void appendChild(DeviceTableItem* item);

    bool set_is_favorite(const QModelIndex &index, bool state);
    void set_use_favorites_only(bool use_favorites_only);

    void emit_call_script(const QModelIndex& index);
};

#endif // DEVICETABLEMODEL_H
