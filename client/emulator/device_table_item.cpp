#include "device_table_item.h"
#include "register_table_item.h"
#include "registers_vector_item.h"
#include "device_item_table_item.h"

#include <QDebug>

DeviceTableItem::DeviceTableItem(Das::Device_Item_Type_Manager *mng, QModbusServer* modbus_server, Das::Device* device, DevicesTableItem *parent)
    : DevicesTableItem(device, parent), enabled_(true), modbus_server_(modbus_server)
{
    auto items = device->items();

    this->init_by_register_type(mng, modbus_server, device, QModbusDataUnit::DiscreteInputs);
    this->init_by_register_type(mng, modbus_server, device, QModbusDataUnit::Coils);
    this->init_by_register_type(mng, modbus_server, device, QModbusDataUnit::InputRegisters);
    this->init_by_register_type(mng, modbus_server, device, QModbusDataUnit::HoldingRegisters);

    update_modbus_server_map();
    QObject::connect(modbus_server, &QModbusServer::dataWritten, this, &DeviceTableItem::update_table_values);
}

void DeviceTableItem::assign(Das::Device* device)
{
    for (int i = 0; i < get_child_count(); ++i)
    {
        RegisterTableItem* item = dynamic_cast<RegisterTableItem*>(get_child(i));
        if (item)
        {
            item->assign(device->items());
        }
    }

    update_modbus_server_map();
}

DevicesTableItem *DeviceTableItem::child(int row) const
{
    int real_row = this->get_real_row(row);
    return this->get_child(real_row);
}

int DeviceTableItem::childCount() const
{
    int non_empty_childs = 0;

    for (int i = 0; i < get_child_count(); i++)
    {
        if (this->get_child(i)->hasChild())
        {
            non_empty_childs++;
        }
    }

    return non_empty_childs;
}

RegisterTableItem *DeviceTableItem::get_child_register_item_by_type(QModbusDataUnit::RegisterType type) const
{
    for (int i = 0; i < get_child_count(); i++)
    {
        RegisterTableItem* item = dynamic_cast<RegisterTableItem*>(get_child(i));
        if (item)
        {
            const RegistersVectorItem* registersItem = static_cast<RegistersVectorItem*>(item->item());
            if (type == registersItem->type())
            {
                return item;
            }
        }
    }

    return nullptr;
}

void DeviceTableItem::init_by_register_type(Das::Device_Item_Type_Manager *mng, QModbusServer *modbus_server, Das::Device *device, QModbusDataUnit::RegisterType registerType)
{
    RegistersVectorItem* registerVectorItem = new RegistersVectorItem(mng, modbus_server, registerType, device->items());
    RegisterTableItem* tableItem = new RegisterTableItem(registerVectorItem, this);
    this->appendChild(tableItem);
}

QModbusDataUnitMap DeviceTableItem::generate_modbus_data_unit_map() const
{
    QModbusDataUnitMap modbus_data_unit_map;
    for (int child_idx = 0; child_idx < get_child_count(); child_idx++)
    {
        RegistersVectorItem* registers_item = static_cast<RegistersVectorItem*>(get_child(child_idx)->item());
        const auto modbus_data_unit = registers_item->modbus_data_unit();

        if (modbus_data_unit.isValid())
            modbus_data_unit_map.insert(registers_item->type(), modbus_data_unit);
    }

    return modbus_data_unit_map;
}

int DeviceTableItem::get_real_row(int row) const
{
    for (int i = 0; i <= row && i < this->get_child_count(); i++)
    {
        if (!this->get_child(row)->hasChild()) {
            row++;
        }
    }

    return row;
}

void DeviceTableItem::update_modbus_server_map()
{
    modbus_server_->setMap(this->generate_modbus_data_unit_map());
}

void DeviceTableItem::update_table_values(QModbusDataUnit::RegisterType type, int address, int size)
{
    bool any_data_changed = false;
    for (int i = 0; i < size; i++)
    {
        if (type == QModbusDataUnit::Coils || type == QModbusDataUnit::HoldingRegisters)
        {
            quint16 value;
            modbus_server_->data(type, address + i, &value);

            RegisterTableItem* table_item_by_type = this->get_child_register_item_by_type(type);
            RegistersVectorItem* registersItem = static_cast<RegistersVectorItem*>(table_item_by_type->item());
            Das::Device_Item* dev_item = registersItem->at(address + i);

            if (dev_item)
            {
                dev_item->set_raw_value(value);
                any_data_changed = true;
            }
        }
    }

    if (any_data_changed)
    {
        emit data_changed(this);
    }
}

Qt::ItemFlags DeviceTableItem::flags(const QModelIndex &index) const {
    Qt::ItemFlags flags = Qt::ItemFlag::ItemIsEnabled;

    if (index.isValid() && index.column() == 0)
    {
        flags |= Qt::ItemFlag::ItemIsUserCheckable;
    }

    return flags;
}

QVariant DeviceTableItem::data(const QModelIndex &index, int role) const {
    if (!index.isValid()) return QVariant();

    if (index.column() == 0)
    {
        if (role == Qt::DisplayRole)
        {
            return "Устройство " + static_cast<Das::Device*>(this->itemData_)->param("address").toString();
        }
        else if (role == Qt::CheckStateRole)
        {
            return static_cast<int>(enabled_ ? Qt::Checked : Qt::Unchecked);
        }
    }

    if (index.column() == 2 && role == Qt::UserRole) return 2;

    return QVariant();
}

bool DeviceTableItem::isUse() const noexcept {
    return this->enabled_;
}

void DeviceTableItem::toggle() noexcept {
    this->enabled_ = !this->enabled_;
}
