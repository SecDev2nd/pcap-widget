#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListView>
#include <QListWidgetItem>
#include <QThread>

#include "pcap_struct.h"

class MainWindow;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class PacketCaptureThread : public QThread
{
    Q_OBJECT

public:
    bool m_stopThread;
    explicit PacketCaptureThread(MainWindow *mainWindow, QObject *parent = nullptr);
    void setThreadFlag(bool flag);

protected:
    void run() override;

private:
    MainWindow *m_mainWindow;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void SearchNIT();
    void print_mac(struct libnet_ethernet_hdr *eth_hdr);
    void print_tcp_port(struct libnet_tcp_hdr *tcp_header);
    void print_inet_ntop(struct libnet_ipv4_hdr *header);
    bool check_tcp(u_int8_t type);
    void print_packet_data();


private slots:
    void on_InterfaceSearchBtn_clicked();
    void on_AttackBtn_clicked();
    void on_AttackStopBtn_clicked();
    void on_listWidget_itemClicked(QListWidgetItem *item);


private:
    Ui::MainWindow *ui;
    PacketCaptureThread *m_captureThread; // PacketCaptureThread 객체의 포인터를 멤버 변수로 추가
};

#endif // MAINWINDOW_H
