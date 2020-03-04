#define CATCH_CONFIG_MAIN
#include "catch2/catch.hpp"
#include <lwip/tcp.h>
#include <lwip/netif.h>
#include <lwip/init.h>
#include <lwip/udp.h>
#include <lwip/sys.h>
#include <lwip/pbuf.h>
#include <thread>
#include <chrono>

void init(){
    static bool initialized = false;
    if(!initialized){
        lwip_init();
        initialized = true;
    }
}

TEST_CASE("Test basic lwip functions"){
    init();
    SECTION("Test max udp_pcb"){
        udp_pcb* u_arr[65536];
        for(int i = 0; i < 65536; i++){
            u_arr[i] = udp_new();
            REQUIRE(u_arr[i] != NULL);
        }
    }
    SECTION("Test max tcp_pcb"){
        tcp_pcb* t_arr[65536];
        for(int i = 0;i < 65536; i++){
            t_arr[i] = tcp_new();
            REQUIRE(t_arr[i] != NULL);
        }
    }
    SECTION("Test max pbuf"){
        pbuf* pbuf_arr[65536];
        for(int i = 0 ;i < 65536; i++){
            pbuf_arr[i] = pbuf_alloc(pbuf_layer::PBUF_TRANSPORT, 1600, pbuf_type::PBUF_RAM);
            REQUIRE(pbuf_arr[i] != NULL);
        }
    }
    SECTION("Test sys_arch"){
        using namespace std::chrono_literals;
        auto before = sys_now();
        std::this_thread::sleep_for(1000ms);
        auto after = sys_now();
        REQUIRE( (after - before < 1100 &&after - before > 900) );
    }
}