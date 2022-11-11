#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "Message.hpp"
#include <json/json.hpp>

std::unique_ptr<sEC> ECsender;
std::unique_ptr<pEC> ECreceiver;
std::vector<unsigned char> aesKEY;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow),
      socket(new QTcpSocket(this))
{
    ui->setupUi(this);
    connect(socket,&QTcpSocket::readyRead,this,&MainWindow::slotReadyRead);
    connect(socket,&QTcpSocket::disconnected,socket,&QTcpSocket::deleteLater);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    socket->connectToHost(ui->lineEdit->text(),1337);
    ECsender = std::make_unique<sEC>(ui->lineEdit_3->text().toStdString(),ui->lineEdit_4->text().toStdString());
    ECreceiver = std::make_unique<pEC>(ui->lineEdit_5->text().toStdString());
    aesKEY = ECsender->Exchange(*ECreceiver);
}

void MainWindow::SendToServer(QString str)
{
    nlohmann::json response;
    std::string text = str.toStdString();
    text.resize(((text.size()+15)/16)*16);
    const std::vector<unsigned char> info(text.begin(),text.end());
    const auto iv = GenerateIV();
    const auto data = aes256_cbc_enc(info,aesKEY,iv);

    Message msg{ECsender->GetKey(),*ECreceiver,data,iv,std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
    msg.signature = ECsender->Sign(msg.GetHash());

    response["sender"] = ECsender->GetPkey();
    response["receiver"] = ECreceiver->GetPkey();
    response["data"] = data;
    response["iv"] = iv;
    response["timestamp"] = msg.timestamp;
    response["signature"] = msg.signature;

    std::string res = response.dump() + "\n";

    QByteArray ba(res.c_str(),res.length());

    socket->write(ba);
}

void MainWindow::slotReadyRead()
{
    QByteArray ba;
    ba = socket->readAll();
    const auto request = QString(ba).toStdString();
    const auto j = nlohmann::json::parse(request);
    if(j.contains("data") && j.contains("iv") && j.contains("timestamp") && j.contains("signature") && j.contains("sender") && j.contains("receiver")){
        if(j["iv"].size()==16 && j["signature"].size()==2){
            const std::string _sender = j["sender"];
            const std::string _receiver = j["receiver"];
            if(_sender == ECreceiver->GetPkey() && _receiver == ECsender->GetPkey()){
                const std::vector<unsigned char> _encData = j["data"];
                const std::array<unsigned char,16> _iv = j["iv"];
                const std::array<std::string,2> _signature = j["signature"];
                const time_t _timestamp = j["timestamp"];
                Message msg{pEC(_sender),pEC(_receiver),_encData,_iv,_timestamp,_signature};
                if(msg.Verify()){
                    std::cout << "VALID!\n";
                    const auto decrypted = aes256_cbc_dec(_encData,aesKEY,_iv);
                    std::string str(decrypted.begin(),decrypted.end());
                    ui->textBrowser->append(QString::fromStdString(str));
                }
            }
        }
    }
}


void MainWindow::on_pushButton_2_clicked()
{
    auto str = ui->lineEdit_2->text();
    ui->textBrowser->append(str);
    if(str!=""){
        SendToServer(str);
    }
    ui->lineEdit_2->clear();
}

