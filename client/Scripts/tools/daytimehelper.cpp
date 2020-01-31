#include <set>
#include <map>

#include <QTimer>

#include <Das/scheme.h>
#include "daytimehelper.h"

namespace Das {

DayTimeHelper::DayTimeHelper(Scheme *prj, QObject *parent) :
    QObject(parent), prj(prj)
{
    m_timer.setSingleShot(true);
    m_timer.setTimerType(Qt::VeryCoarseTimer);
    connect(&m_timer, &QTimer::timeout, this, &DayTimeHelper::onTimer);
}

void DayTimeHelper::stop()
{
    if (m_timer.isActive())
        m_timer.stop();
}

void DayTimeHelper::init()
{
    stop();

    qint64 current_secs, zero_secs, day_secs, night_secs, min_secs;

    QDateTime current = QDateTime::currentDateTime();
    current_secs = (current.toMSecsSinceEpoch() / 1000) + 1;

    current.setTime({0, 0});
    zero_secs = current.toMSecsSinceEpoch() / 1000;

    bool next_secs_flag = false;
    qint64 next_secs = 0;

    for (Section* sct: prj->sections())
    {
        day_secs = zero_secs + sct->day_time()->start();
        night_secs = zero_secs + sct->day_time()->end();

        if (current_secs >= night_secs)
            night_secs += 24 * 60 * 60;

        if (current_secs >= day_secs)
            day_secs += 24 * 60 * 60;

        min_secs = std::min(day_secs, night_secs);
        if (!next_secs_flag || next_secs > min_secs) {
            next_secs = min_secs;
            next_secs_flag = true;
        }
    }

    if (next_secs_flag)
    {
        m_timer.setInterval((next_secs - current_secs) * 1000);
        if (m_timer.interval() < 3000)
            qCritical() << "DayTimeHelper interval is too small" << m_timer.interval() << current_secs << next_secs;
//        qDebug() << "Day part will change in" << QDateTime::fromSecsSinceEpoch(next_secs.value()).toString() << "ms:" << m_timer.interval();
        m_timer.start();
    }
    else
        qWarning() << "DayTimeHelper empty";
}

void DayTimeHelper::onTimer()
{
    QDateTime current = QDateTime::currentDateTime();
    qint64 current_secs = current.toMSecsSinceEpoch() * 1000;

    current.setTime({0, 0});
    qint64 zero_secs = current.toMSecsSinceEpoch() * 1000;

    qint64 value_secs;
    auto checkDayPartChanged = [&](qint64 value) {
        value_secs = zero_secs + value;
        return value_secs >= (current_secs - 1) && value_secs <= (current_secs + 1);
    };

    for (Section* sct: prj->sections())
    {
        if (checkDayPartChanged(sct->day_time()->start()))
            emit onDayPartChanged(sct, true);

        if (checkDayPartChanged(sct->day_time()->end()))
            emit onDayPartChanged(sct, false);
    }

//    qDebug() << "Day part changed in" << QDateTime::currentDateTime().toString();
    init();
}

} // namespace Das
