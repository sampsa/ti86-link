/* Copyrigth (C) 1014 Sampsa Vierros
 * Licence: GNU GPL v2
*/

#define F_CPU 12000000

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include <util/delay.h>
#include <inttypes.h>

#include "usbdrv.h"

// Input and output pins must be within the same port
#define LINK_PORT      PORTB
#define LINK_PIN       PINB
#define LINK_DDR       DDRB

#define WHITE_IN       PB2
#define RED_IN         PB3
#define WHITE_OUT      PB1
#define RED_OUT        PB0

#define IN_MASK        ((1 << WHITE_IN) | (1 << RED_IN))
#define OUT_MASK       ((1 << WHITE_OUT) | (1 << RED_OUT))

#define RED_IN_MASK    (1 << RED_IN)
#define WHITE_IN_MASK  (1 << WHITE_IN)
#define RED_OUT_MASK   (1 << RED_OUT)
#define WHITE_OUT_MASK (1 << WHITE_OUT)

#define LED_PORT       PORTD
#define LED_DDR        DDRD
#define LED1           PD5
#define LED2           PD4

#define RQ_STATUS      0
#define RQ_DATA_WRITE  1
#define RQ_DATA_READ   2
#define RQ_BUF_LEN     3
#define RQ_SET_DELAY   4

#define STATUS_IDLE    0
#define STATUS_WRITING 1	// Device is still writing previous data
#define STATUS_WAITING 2    // Device is waiting data from host
#define STATUS_READING 3	// Device is in the middle of receiving a byte
#define STATUS_PENDING 4	// Device has data ready to send

#define MAX_MSG_LEN    1 
#define STATUS_MSG_LEN 1
#define INFO_MSG_LEN   1
static uint8_t msg[MAX_MSG_LEN];
uint8_t device_status;

#define BUFFER_LEN 8
static uint8_t buffer[BUFFER_LEN];
uint8_t buf_len;
uint8_t buf_offset;

#define BIT_DELAY 10
uint8_t delay;

void delay_us(uint8_t us)
{
	volatile uint16_t i;
	while (us != 0) {
		for (i=0; i != 12; i++);
		us--;
	}
}

USB_PUBLIC uchar usbFunctionSetup(uchar data[8])
{
	uint8_t tmp;
	usbRequest_t *rq = (void *)data;
	switch(rq->bRequest) {
	case RQ_STATUS:
		msg[0] = device_status;
		usbMsgPtr = (usbMsgPtr_t)msg;
		return STATUS_MSG_LEN;
	case RQ_BUF_LEN:
		msg[0] = BUFFER_LEN;
		usbMsgPtr = (usbMsgPtr_t)msg;
		return INFO_MSG_LEN;
	case RQ_SET_DELAY:
		delay = (uint8_t)rq->wIndex.word;
		return 0;
	case RQ_DATA_WRITE:
		device_status = STATUS_WAITING;
		return USB_NO_MSG;
	case RQ_DATA_READ:
		usbMsgPtr = (usbMsgPtr_t)buffer;
		device_status = STATUS_IDLE;
		tmp = buf_len;
		buf_len = 0;
		return tmp;
	}
	return 0;
}

USB_PUBLIC uchar usbFunctionWrite(uchar *data, uchar len)
{
	uchar i;
	for(i=0; i<len; i++) {
		buffer[i] = data[i];
	}
	buf_len = len;
	buf_offset = 0;
	device_status = STATUS_WRITING;
	return 1;
}

uint8_t rcv(void)
{
	delay_us(delay);
	// If red is low, zero bit is being transmitted and if white is low one.
	uint8_t white_in = WHITE_IN_MASK;
	uint8_t red_in = RED_IN_MASK;
	uint8_t white_out = WHITE_OUT_MASK;
	if((LINK_PIN & RED_IN_MASK) != 0) {
		// Swap pins, TODO: Investigate if XOR swap is faster
		white_in = RED_IN_MASK;
		red_in = WHITE_IN_MASK;
		white_out = RED_OUT_MASK;
	}
	// Do the procedure as if a zero was being sent. 
	LINK_PORT ^= white_out;                         // Set white to low
	delay_us(delay);
	while((LINK_PIN & red_in) != red_in) {          // Wait until red is high
		__asm__ volatile ("nop\n"::); 
	}
	delay_us(delay);
	LINK_PORT ^= white_out;                         // Set white back to high
	if(white_in == WHITE_IN_MASK) {
		return 0x0;
	} else {
		return 0x1;
	}
}

void snd(uint8_t bit)
{
	// If zero bit is being sent, start by setting red to low 
	uint8_t white_in = WHITE_IN_MASK;
	uint8_t red_out = RED_OUT_MASK;
	if(bit != 0) {
		white_in = RED_IN_MASK;
		red_out = WHITE_OUT_MASK;	
	}
	// Do the procedure as if a zero was being sent.
	LINK_PORT ^= red_out;                         // Set red to low
	delay_us(delay);
	while((LINK_PIN & white_in) == white_in) {    // Wait until white is low
		__asm__ volatile ("nop\n"::);
	}
	delay_us(delay);
	LINK_PORT ^= red_out;                         // Set red back to high
	delay_us(delay);
	while((LINK_PIN & white_in) != white_in) {    // Wait until white is high
		__asm__ volatile ("nop\n"::);
	}
}

void receive(void)
{
	if(buf_len == BUFFER_LEN) {
		device_status = STATUS_PENDING;
		return;
	}
	uint8_t byte=0;
	for(uint8_t bit=0; bit<8; bit++) {
		// Least significant bit is transmitted first.
		byte |= (rcv() << bit);
	}
	buffer[buf_len] = byte;
	buf_len += 1;
}

void send(uint8_t byte)
{
	for(uint8_t bit=0; bit<8; bit++) {
		// Least significant bit is transmitted first.
		snd(byte & (1 << bit));
	}
}

int main()
{
	buf_len = 0;
	buf_offset = 0;
	device_status = STATUS_IDLE;
	delay = BIT_DELAY;
	
	// Configure pin mode for link pins and enable pull-up resistors for input
	// pins.
	LINK_DDR &= ~IN_MASK;
	LINK_DDR |= OUT_MASK;
	LINK_PORT &= ~OUT_MASK;
	
	LED_DDR |= ((1 << LED1) | (1 << LED2));
	LED_PORT &= ~((1 << LED1) | (1 << LED2));

	wdt_enable(WDTO_1S);
	usbInit();

	usbDeviceDisconnect();
	uint8_t i;
	for(i = 0; i<250; i++) {
		wdt_reset();
		_delay_ms(2);
	}
	usbDeviceConnect();
	sei();

	for(;;) {
		if(device_status != STATUS_WRITING) {
			// If we are not writing, logic zero at either input pin indicates
			// incoming data from calculator.
			uint8_t status = LINK_PIN;
			if((status & IN_MASK) != IN_MASK) {
				LED_PORT |= (1 << LED1);
				device_status = STATUS_READING;
				receive();
				device_status = STATUS_PENDING;
				LED_PORT ^= (1 << LED1);
			}
		} else { 
			if(buf_offset == buf_len) {
				buf_offset = 0;
				buf_len = 0;
				device_status = STATUS_IDLE;
			} else {
				LED_PORT |= (1 << LED2);
				send(buffer[buf_offset]);
				buf_offset += 1;
				LED_PORT ^= (1 << LED2);
			}
		}
		
		wdt_reset();
		usbPoll();
	}

	return 0;
}
