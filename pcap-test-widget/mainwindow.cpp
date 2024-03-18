#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap_struct.h"

char* NITname;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    m_captureThread = new PacketCaptureThread(this);
}

MainWindow::~MainWindow()
{
    delete ui;
    delete m_captureThread;
}

void MainWindow::SearchNIT(){
    struct ifaddrs *addrs, *tmp;
    getifaddrs(&addrs);
    tmp = addrs;
    while(tmp)
    {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
            QString interfaceName = QString::fromUtf8(tmp->ifa_name);
            ui->listWidget->addItem(interfaceName);
        }
        tmp = tmp->ifa_next;
    }
    freeifaddrs(addrs);
}

void MainWindow::print_mac(struct libnet_ethernet_hdr *eth_hdr){
    u_int8_t *src = eth_hdr->ether_shost;
    u_int8_t *dst = eth_hdr->ether_dhost;
    QString macInfo = QString("MAC: %1:%2:%3:%4:%5:%6 ---> %7:%8:%9:%10:%11:%12")
                          .arg(src[0], 2, 16, QLatin1Char('0'))
                          .arg(src[1], 2, 16, QLatin1Char('0'))
                          .arg(src[2], 2, 16, QLatin1Char('0'))
                          .arg(src[3], 2, 16, QLatin1Char('0'))
                          .arg(src[4], 2, 16, QLatin1Char('0'))
                          .arg(src[5], 2, 16, QLatin1Char('0'))
                          .arg(dst[0], 2, 16, QLatin1Char('0'))
                          .arg(dst[1], 2, 16, QLatin1Char('0'))
                          .arg(dst[2], 2, 16, QLatin1Char('0'))
                          .arg(dst[3], 2, 16, QLatin1Char('0'))
                          .arg(dst[4], 2, 16, QLatin1Char('0'))
                          .arg(dst[5], 2, 16, QLatin1Char('0'));
    ui->listWidget_2->addItem(macInfo);

}

void MainWindow::print_tcp_port(libnet_tcp_hdr *tcp_header){
    QString portInfo = QString("PORT: %1\t---> %2")
                           .arg(ntohs(tcp_header->th_sport))
                           .arg(ntohs(tcp_header->th_dport));
    ui->listWidget_2->addItem(portInfo);
}

void MainWindow::print_inet_ntop(libnet_ipv4_hdr *ip_header){
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    QString ipInfo = QString("IP: %1 ---> %2")
                         .arg(QString(src_ip))
                         .arg(QString(dst_ip));
    ui->listWidget_2->addItem(ipInfo);
}


bool MainWindow::check_tcp(u_int8_t type) {
    return type == 6;
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};
void PacketCaptureThread::setThreadFlag(bool flag)
{
    m_stopThread = flag;
}

void MainWindow::print_packet_data(){
    char errbuf[PCAP_ERRBUF_SIZE];
    int cnt = 0;
    param.dev_ = NITname;

    //open pcap for captured packet
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        QString errorMessage = QString("pcap_open_live(%1) returned null - %2").arg(param.dev_).arg(errbuf);
        QMessageBox::critical(this, "Error", errorMessage);
        exit(1);
    }


    // pacp capturing....
    while (m_captureThread->m_stopThread) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        ui->lcdNumber->display(cnt++);
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet+sizeof(*eth_hdr));
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet+sizeof(*ip_hdr)+sizeof(*eth_hdr));


        if (check_tcp(ip_hdr->ip_p)) { //*ip_p -> protocol */
            u_int32_t total_length = header->caplen; //캡쳐된 패킷 길이(실제 길이랑은 다름)
            u_int32_t header_length = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4; //헤더의 총 길이
            u_int32_t payload_length = total_length - header_length;

            QString payloadInfo;
            if (payload_length == 0) {
                payloadInfo = "Payload: 0 Byte";
            } else if (payload_length < 10) {
                payloadInfo = "Payload: ";
                for (u_int32_t i = header_length; i < header_length + payload_length; i++) { // i 변수 형식 수정
                    payloadInfo += QString("|%1").arg(packet[i], 2, 16, QLatin1Char('0'));
                }
            } else {
                payloadInfo = "Payload: ";
                for (u_int32_t i = header_length; i < header_length + 10; i++) { // i 변수 형식 수정
                    payloadInfo += QString("|%1").arg(packet[i], 2, 16, QLatin1Char('0'));
                }
                payloadInfo += " ..."; // 페이로드가 잘림을 나타냄
            }

            ui->listWidget_2->addItem(QString("%1 bytes captured").arg(total_length));
            ui->listWidget_2->addItem("Protocol: TCP");
            print_mac(eth_hdr);
            print_tcp_port(tcp_hdr);
            print_inet_ntop(ip_hdr);
            ui->listWidget_2->addItem(payloadInfo);
            ui->listWidget_2->addItem("");
        }
    }
    pcap_close(pcap);
}

PacketCaptureThread::PacketCaptureThread(MainWindow *mainWindow, QObject *parent)
    : QThread(parent), m_mainWindow(mainWindow)
{
    // 생성자 내용은 그대로 유지
}


void PacketCaptureThread::run()
{
    setThreadFlag(true);
    m_mainWindow->print_packet_data();
}

void MainWindow::on_InterfaceSearchBtn_clicked()
{
    SearchNIT();
}

void MainWindow::on_AttackBtn_clicked()
{

    m_captureThread->start();
}


void MainWindow::on_AttackStopBtn_clicked()
{
    m_captureThread->setThreadFlag(false);
}

void MainWindow::on_listWidget_itemClicked(QListWidgetItem *item)
{
    QListWidgetItem *item2 = ui->listWidget->currentItem();
    if (item2) {
        const QByteArray byteArray = item2->text().toUtf8();
        NITname = strdup(byteArray.constData());
    }
}
