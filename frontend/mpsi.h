#include "cryptoTools/Common/CLP.h"
#include "volePSI/RsPsi.h"
#include <fstream>
#include "coproto/Socket/AsioSocket.h"
#include "volePSI/fileBased.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CLP.h"
#include "volePSI/RsOprf.h"
#include "volePSI/RsOpprf.h"
#include <iomanip>
#include <thread>
#include <mutex>
using namespace oc;
using namespace volePSI;
using namespace osuCrypto;


void printVector(std::string s, std::vector<block> v){
    s = s + ": ";
    std::cout << s;
    std::string fill(s.length(), ' ');
    for (auto i = 0; i < v.size(); ++i){
        if (i % 4 == 0){
            std::cout << std::endl;
            std::cout << fill;
        }
        std::cout << v[i] << " ";
    }
    std::cout << std::endl;
}

void printBlock(std::string s, block v){
    s = s + ": ";
    std::cout << v;
    std::cout << std::endl;
}

std::vector<std::string> readIP(const std::string& ipPath){
    std::vector<std::string> IPs;
    std::ifstream file(ipPath, std::ios::in);
    if (file.is_open() == false)
        throw std::runtime_error("failed to open file: " + ipPath);
    std::string buffer;
    while (std::getline(file, buffer))
    {
        IPs.push_back(buffer);
    }
    file.close();
    return IPs;
}

std::vector<block> readSet(const std::string& setPath)
{
    std::vector<block> ret;
    RandomOracle hash;

    std::ifstream file(setPath, std::ios::in);
    if (file.is_open() == false)
      throw std::runtime_error("failed to open file: " + setPath);
    std::string buffer;
    while (std::getline(file, buffer))
    {
      hash.Reset();
      hash.Update((const u8*)buffer.data(), buffer.size());
      u8 tempdata[20];
      hash.Final(tempdata);
      block data;
      memcpy(&data, tempdata, sizeof(block));
      ret.push_back(data);
    }
    file.close();
    return ret;
}

void write(std::string filename, std::vector<std::string> &data){
    std::ofstream outFile;
    outFile.open(filename,std::ios::out);
    for (int i = 0; i < data.size(); i++){
        if (i == data.size()-1) 
            outFile << data[i];
        else 
            outFile << data[i] << std::endl;
	}
    outFile.close();
}


void encode(const std::vector<block>& key, const std::vector<block>& value, std::vector<block>& OKVStable){
    PRNG prng(oc::sysRandomSeed());
    u64 n = key.size();
    u64 w = 3, ssp = 40, nt = 1, binSize = 1 << 15;
    auto dt = PaxosParam::GF128; // Binary will have stronger adaptability, but GF128 is faster.
    u64 baxosSize;
    {
        Baxos paxos;
        paxos.init(n, binSize, w, ssp, dt, oc::ZeroBlock);
        baxosSize = paxos.size();
    }
    OKVStable.resize(baxosSize);
    Baxos paxos;
    paxos.init(n, binSize, w, ssp, dt, block(0, 0));
    paxos.solve<block>(key, value, OKVStable, &prng, nt);// Notice that if nt = 4, it will happen segmentation fault.
}

void decode(const std::vector<block>& key, std::vector<block>& value, const std::vector<block>& OKVStable){
    u64 n = key.size();
    u64 w = 3, ssp = 40, nt = 1, binSize = 1 << 15;
    auto dt = PaxosParam::GF128;
    u64 baxosSize;
    {
        Baxos paxos;
        paxos.init(n, binSize, w, ssp, dt, oc::ZeroBlock);
        baxosSize = paxos.size();
    }
    Baxos paxos;
    paxos.init(n, binSize, w, ssp, dt, block(0, 0));
    paxos.decode<block>(key, value, OKVStable, nt);
}

void fillRecvOPPRF(int i, int k, std::vector<block>& inputSet, std::vector<std::vector<block>>& recvOPPRF, std::vector<coproto::Socket>& OPPRFServers, std::vector<RsOpprfReceiver>& recver, std::atomic<int>& commu) {
    recvOPPRF[i].resize(k);
    std::string ip = "localhost:" + std::to_string(2000 + i);
    OPPRFServers[i] = coproto::asioConnect(ip, 1);
    PRNG prng1(block(i, i + 1));
    macoro::sync_wait(recver[i].receive(k, inputSet, recvOPPRF[i], prng1, 1, OPPRFServers[i]));
    commu += OPPRFServers[i].bytesSent();
    macoro::sync_wait(OPPRFServers[i].flush());
}

void malcol_MPSI(const oc::CLP& cmd)
{
    Timer timer;
    auto k = cmd.get<int>("k");
    auto pIDx = cmd.get<int>("p");  // the party index
    auto n = cmd.get<int>("n");  // the number of parties
    auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);
    //auto t = cmd.get<int>("t"); // collusion threshold
    //auto v = n - t;  // the number of honest parties
    // u64 w = 3, binSize = 1 << 15;
    // auto dt = PaxosParam::GF128;
    // u64 baxosSize;
    // {
    //     Baxos paxos;
    //     paxos.init(n, binSize, w, ssp, dt, oc::ZeroBlock);
    //     baxosSize = paxos.size();
    // }
    std::vector<coproto::Socket> KeyChlClients(n);
    std::vector<coproto::Socket> KeyChlServers(n);
    std::vector<block> sharingKey(n);
    PRNG prng((block)(pIDx));
    prng.get(sharingKey.data(), sharingKey.size());
    std::atomic<int> commu(0);
    std::vector<block> inputSet(k);
    for (auto i = 0; i < 100; ++i){
        inputSet[i] = (block) (100 + i);
    }
    for (auto i = 100; i < k; ++i){
        inputSet[i] = prng.get<block>();
    }

    auto start = timer.setTimePoint("start");
    auto end = start;

    //zero-sharing
    for (auto i = 0; i < pIDx; i++){
        std::string ip = "localhost:" + std::to_string(1212 * i + pIDx);
        KeyChlServers[i] = coproto::asioConnect(ip, 1);
        macoro::sync_wait(KeyChlServers[i].recv(sharingKey[i]));
        commu += KeyChlServers[i].bytesSent();
    }
    for (auto i = pIDx + 1; i < n; i++){
        std::string ip = "localhost:" + std::to_string(1212 * pIDx + i);
        KeyChlClients[i] = coproto::asioConnect(ip, 0);
        macoro::sync_wait(KeyChlClients[i].send(sharingKey[i]));
        commu += KeyChlClients[i].bytesSent();
    }
    AES aes;
    std::vector<block> sh(k);
    for (auto h = 0; h < k; ++h){
        for (auto i = 0; i < n; ++i){
            if (i == pIDx) continue;
            block temp;
            aes.setKey(sharingKey[i]);
            aes.ecbEncBlock(inputSet[h], temp);
            sh[h] = sh[h] ^ temp;
        }
    }
    timer.setTimePoint("zero-sharing done");
    //opprf  P_i  and  P_{n-1} , i = 0, 1, ..., n-2
    if (pIDx < n - 1){
        std::string ip = "localhost:" + std::to_string(2000 + pIDx);
        coproto::Socket OPPRFClient;
        RsOpprfSender sender;
        OPPRFClient = coproto::asioConnect(ip, 0);
        PRNG prng0(block(pIDx, pIDx));
        macoro::sync_wait(sender.send(k, inputSet, sh, prng0, 1, OPPRFClient));
        commu += OPPRFClient.bytesSent();
        macoro::sync_wait(OPPRFClient.flush());
    }

    if (pIDx == n - 1){
        std::vector<block> intersection;
        std::vector<std::vector<block>> recvOPPRF(n);
        std::vector<coproto::Socket> OPPRFServers(n);
        std::vector<RsOpprfReceiver> recver(n);

        // multi-thread
        std::vector<std::thread> threads;
        for (auto i = 0; i < n - 1; i++) {
            threads.emplace_back(fillRecvOPPRF, i, k, std::ref(inputSet), std::ref(recvOPPRF), std::ref(OPPRFServers), std::ref(recver), std::ref(commu));
        }
        for (auto& thread : threads) {
            thread.join();
        }

        // single thread
        // for (auto i = 0; i < n - 1; i++){
        //     recvOPPRF[i].resize(k);
        //     std::string ip = "localhost:" + std::to_string(2000 + i);
        //     OPPRFServers[i] = coproto::asioConnect(ip, 1);
        //     PRNG prng1(block(i, i + 1));
        //     macoro::sync_wait(recver[i].receive(k, inputSet, recvOPPRF[i], prng1, 1, OPPRFServers[i]));
        //     //commu += OPPRFServers[i].bytesSent();
        //     macoro::sync_wait(OPPRFServers[i].flush());
        //     //std::cout << i << "OPPRF recv done" << std::endl;
        // }
        
        for (auto i = 0; i < k; ++i){
            block tempXOR =(block) 0;
            for (auto j = 0; j < n - 1; j++)
                tempXOR = tempXOR ^ recvOPPRF[j][i];
            if (sh[i] == tempXOR)
                intersection.push_back(inputSet[i]);
        }
        
        std::cout << "intersection size: " << intersection.size() << std::endl;
    }
    end = timer.setTimePoint("opprf done");
    if (v)
        std::cout << timer << std::endl;
    auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
	std::cout << "total time " << tt << "ms" << std::endl;
    std::cout << "total commu " << commu << "bytes" << std::endl;
}

