#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>

#include "sph_keccak.h"


static void keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash[32];	
   
    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 80);
    sph_keccak256_close(&ctx_keccak, hash);

    memcpy(state, hash, 32);
}

void uartwrite(volatile uint32_t* uartlite_addr, uint32_t data) {
	uartlite_addr[4>>2] = (data & 0xff000000) >> 24;
	usleep(100);
	uartlite_addr[4>>2] = (data & 0xff0000) >> 16;
	usleep(100);
	uartlite_addr[4>>2] = (data & 0xff00) >> 8;
	usleep(100);
	uartlite_addr[4>>2] = (data & 0xff);
	usleep(100);
}

void wait_for_uartrx(volatile uint32_t* uartlite_addr, volatile uint32_t* force_end_addr, int thr_id) {
	for (;;) {
		if (work_restart[thr_id].restart) {
			force_end_addr[0] = 0xffffffff;
		}
		uint32_t status = uartlite_addr[0x8 >> 2];
		if (status & 0x1) break; // Has data
		usleep(5000);
	}
	usleep(10000);
}

int scanhash_keccak(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	printf("scanhash_keccak: thr_id: %d\n", thr_id);
	int dh = open("/dev/mem", O_RDWR | O_SYNC); // Open /dev/mem which represents the whole physical memory
	volatile uint32_t* uartlite_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, 0x42c00000); // Memory map source address
	volatile uint32_t* max_nonce_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, 0x41260000); // Memory map source address
	volatile uint32_t* xadc_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, 0x43c00000); // Memory map source address
	volatile uint32_t* force_end_addr  = mmap(NULL, 65535, PROT_READ | PROT_WRITE, MAP_SHARED, dh, 0x41250000); // Memory map source address
	force_end_addr[0] = 0;

	/*pdata[0] = 0x70000000;
	pdata[1] = 0x6e7d744e;
	pdata[2] = 0xea3d6005;
	pdata[3] = 0x2ab532b;
	pdata[4] = 0x1d92097c;
	pdata[5] = 0x6e396fb2;
	pdata[6] = 0xd52ceea6;
	pdata[7] = 0x308e0200;
	pdata[8] = 0;
	pdata[9] = 0x2b0cbe12;
	pdata[10] = 0xf497f186;
	pdata[11] = 0x1741217;
	pdata[12] = 0x17d9618e;
	pdata[13] = 0x4e205277;
	pdata[14] = 0xef6bc2e9;
	pdata[15] = 0xf504f6ed;
	pdata[16] = 0x1813effe;
	pdata[17] = 0x1b3b085b;
	pdata[18] = 0x67d4041b;
	pdata[19] = 0x1aca300;*/

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];
	const uint32_t Htarg = ptarget[6];
	printf("first_nonce: %x\n", first_nonce);
	printf("Htarg: %x\n", Htarg);
	printf("max_nonce: %x\n", max_nonce);
	for (int i = 0; i < 19; i++) {
		printf("pdata[%d] = %x\n", i, pdata[i]);
	}

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	for (int i = 0; i < 8; i++) {
		printf("ptarget[%d] = %x\n", i, ptarget[i]);
	}

	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
	
	printf("Clearing RX/TX Fifo\n");
	uartlite_addr[0xc >> 2] |= (1 << 0) | (1 << 1);
	max_nonce_addr[0 >> 2] = max_nonce;
/*do {
	
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		keccakhash(hash64, &endiandata);
                if (((hash64[7]&0xFFFFFF00)==0) && 
				fulltest(hash64, ptarget)) {
                       *hashes_done = n - first_nonce + 1;
		       printf("nonce: %x\n", n);
		for (int i = 0; i < 8; i++) {
			printf("hash64[%d] = %x\n", i, hash64[i]);
		}
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
*/
	printf("Sending to PL\n");
	for (int i = 0; i < 19; i++) {
		uartwrite(uartlite_addr, pdata[i]);
	}
	uartwrite(uartlite_addr, first_nonce);
	uartwrite(uartlite_addr, Htarg);
	
	printf("Waiting for uartrx\n");
	wait_for_uartrx(uartlite_addr, force_end_addr, thr_id);
	uint32_t golden_nonce = 0;
	golden_nonce |= (uartlite_addr[0] << 24);
	golden_nonce |= (uartlite_addr[0] << 16);
	golden_nonce |= (uartlite_addr[0] << 8);
	golden_nonce |= (uartlite_addr[0]);
	printf("Golden nonce: %x\n", golden_nonce);
	printf("VCCINT: %d, VCCINT PSS Core: %d, temperature: %d\n", xadc_addr[0x204>>2], xadc_addr[0x234>>2], xadc_addr[0x200]);

	uint32_t temperature = 0;
	temperature |= (uartlite_addr[0] << 24);
	temperature |= (uartlite_addr[0] << 16);
	temperature |= (uartlite_addr[0] << 8);
	temperature |= (uartlite_addr[0]);
	munmap((void*)uartlite_addr, 65535);
	close(dh);


	if (golden_nonce == 0xffffffff) {
		n = max_nonce;
	} else {
		n = golden_nonce-49;
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	if (golden_nonce != 0xffffffff) {
		printf("Maybe hash!\n");
		uint32_t old_n = n;
		for (int j = -60; j < 100; j++) {
			n = old_n + j;
			be32enc(&endiandata[19], n); 
			keccakhash(hash64, &endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && fulltest(hash64, ptarget)) {
				printf("WOOP SUCCESS!!!, n = %x, j = %d\n", n, j);
				*hashes_done = n - first_nonce + 1;
				for (int i = 0; i < 8; i++) {
					printf("hash64[%d] = %x\n", i, hash64[i]);
				}
				return true;
			}
		}
	}
	return 0;
}
