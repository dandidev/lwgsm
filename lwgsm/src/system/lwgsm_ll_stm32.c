/**
 * \file            lwgsm_ll_stm32.c
 * \brief           Generic STM32 driver, included in various STM32 driver variants
 */

/*
 * Copyright (c) 2022 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * This file is part of LwGSM - Lightweight GSM-AT library.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         v0.1.1
 */

/*
 * How it works
 *
 * On first call to \ref lwgsm_ll_init, new thread is created and processed in usart_ll_thread function.
 * USART is configured in RX DMA mode and any incoming bytes are processed inside thread function.
 * DMA and USART implement interrupt handlers to notify main thread about new data ready to send to upper layer.
 *
 * More about UART + RX DMA: https://github.com/MaJerle/stm32-usart-dma-rx-tx
 *
 * \ref LWGSM_CFG_INPUT_USE_PROCESS must be enabled in `lwgsm_config.h` to use this driver.
 */
#include "lwgsm/lwgsm.h"
#include "lwgsm/lwgsm_mem.h"
#include "lwgsm/lwgsm_input.h"
#include "system/lwgsm_ll.h"

#if !__DOXYGEN__

#if !LWGSM_CFG_INPUT_USE_PROCESS
#error "LWGSM_CFG_INPUT_USE_PROCESS must be enabled in `lwgsm_config.h` to use this driver."
#endif /* LWGSM_CFG_INPUT_USE_PROCESS */

#if !defined(LWGSM_USART_DMA_RX_BUFF_SIZE)
#define LWGSM_USART_DMA_RX_BUFF_SIZE      0x1000
#endif /* !defined(LWGSM_USART_DMA_RX_BUFF_SIZE) */

#if !defined(LWGSM_MEM_SIZE)
#define LWGSM_MEM_SIZE                    0x1000
#endif /* !defined(LWGSM_MEM_SIZE) */

#if !defined(LWGSM_USART_RDR_NAME)
#define LWGSM_USART_RDR_NAME              RDR
#endif /* !defined(LWGSM_USART_RDR_NAME) */

/* USART memory */
static uint8_t      usart_mem[LWGSM_USART_DMA_RX_BUFF_SIZE];
static uint8_t      is_running, initialized;
static size_t       old_pos;

/* USART thread */
static void usart_ll_thread(void* arg);
static osThreadId_t usart_ll_thread_id;

/* Message queue */
static osMessageQueueId_t usart_ll_mbox_id;

/**
 * \brief           USART data processing
 */
static void
usart_ll_thread(void* arg) {
    size_t pos;

    LWGSM_UNUSED(arg);

    while (1) {
        void* d;
        /* Wait for the event message from DMA or USART */
        osMessageQueueGet(usart_ll_mbox_id, &d, NULL, osWaitForever);

        /* Read data */
#if defined(LWGSM_USART_DMA_RX_STREAM)
        pos = sizeof(usart_mem) - LL_DMA_GetDataLength(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
#else
        pos = sizeof(usart_mem) - LL_DMA_GetDataLength(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
#endif /* defined(LWGSM_USART_DMA_RX_STREAM) */
        if (pos != old_pos && is_running) {
            if (pos > old_pos) {
                lwgsm_input_process(&usart_mem[old_pos], pos - old_pos);
            } else {
                lwgsm_input_process(&usart_mem[old_pos], sizeof(usart_mem) - old_pos);
                if (pos > 0) {
                    lwgsm_input_process(&usart_mem[0], pos);
                }
            }
            old_pos = pos;
            if (old_pos == sizeof(usart_mem)) {
                old_pos = 0;
            }
        }
    }
}

/**
 * \brief           Configure UART using DMA for receive in double buffer mode and IDLE line detection
 */
static void
configure_uart(uint32_t baudrate) {
    static LL_USART_InitTypeDef usart_init;
    static LL_DMA_InitTypeDef dma_init;
    LL_GPIO_InitTypeDef gpio_init;

    if (!initialized) {
        /* Enable peripheral clocks */
        LWGSM_USART_CLK;
        LWGSM_USART_DMA_CLK;
        LWGSM_USART_TX_PORT_CLK;
        LWGSM_USART_RX_PORT_CLK;

#if defined(LWGSM_RESET_PIN)
        LWGSM_RESET_PORT_CLK;
#endif /* defined(LWGSM_RESET_PIN) */

        /* Global pin configuration */
        LL_GPIO_StructInit(&gpio_init);
        gpio_init.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
        gpio_init.Pull = LL_GPIO_PULL_UP;
        gpio_init.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
        gpio_init.Mode = LL_GPIO_MODE_OUTPUT;

#if defined(LWGSM_RESET_PIN)
        /* Configure RESET pin */
        gpio_init.Pin = LWGSM_RESET_PIN;
        LL_GPIO_Init(LWGSM_RESET_PORT, &gpio_init);
#endif /* defined(LWGSM_RESET_PIN) */

        /* Configure USART pins */
        gpio_init.Mode = LL_GPIO_MODE_ALTERNATE;

        /* TX PIN */
        gpio_init.Alternate = LWGSM_USART_TX_PIN_AF;
        gpio_init.Pin = LWGSM_USART_TX_PIN;
        LL_GPIO_Init(LWGSM_USART_TX_PORT, &gpio_init);

        /* RX PIN */
        gpio_init.Alternate = LWGSM_USART_RX_PIN_AF;
        gpio_init.Pin = LWGSM_USART_RX_PIN;
        LL_GPIO_Init(LWGSM_USART_RX_PORT, &gpio_init);

        /* Configure UART */
        LL_USART_DeInit(LWGSM_USART);
        LL_USART_StructInit(&usart_init);
        usart_init.BaudRate = baudrate;
        usart_init.DataWidth = LL_USART_DATAWIDTH_8B;
        usart_init.HardwareFlowControl = LL_USART_HWCONTROL_NONE;
        usart_init.OverSampling = LL_USART_OVERSAMPLING_16;
        usart_init.Parity = LL_USART_PARITY_NONE;
        usart_init.StopBits = LL_USART_STOPBITS_1;
        usart_init.TransferDirection = LL_USART_DIRECTION_TX_RX;
        LL_USART_Init(LWGSM_USART, &usart_init);

        /* Enable USART interrupts and DMA request */
        LL_USART_EnableIT_IDLE(LWGSM_USART);
        LL_USART_EnableIT_PE(LWGSM_USART);
        LL_USART_EnableIT_ERROR(LWGSM_USART);
        LL_USART_EnableDMAReq_RX(LWGSM_USART);

        /* Enable USART interrupts */
        NVIC_SetPriority(LWGSM_USART_IRQ, NVIC_EncodePriority(NVIC_GetPriorityGrouping(), 0x07, 0x00));
        NVIC_EnableIRQ(LWGSM_USART_IRQ);

        /* Configure DMA */
        is_running = 0;
#if defined(LWGSM_USART_DMA_RX_STREAM)
        LL_DMA_DeInit(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
        dma_init.Channel = LWGSM_USART_DMA_RX_CH;
#else
        LL_DMA_DeInit(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
        dma_init.PeriphRequest = LWGSM_USART_DMA_RX_REQ_NUM;
#endif /* defined(LWGSM_USART_DMA_RX_STREAM) */
        dma_init.PeriphOrM2MSrcAddress = (uint32_t)&LWGSM_USART->LWGSM_USART_RDR_NAME;
        dma_init.MemoryOrM2MDstAddress = (uint32_t)usart_mem;
        dma_init.Direction = LL_DMA_DIRECTION_PERIPH_TO_MEMORY;
        dma_init.Mode = LL_DMA_MODE_CIRCULAR;
        dma_init.PeriphOrM2MSrcIncMode = LL_DMA_PERIPH_NOINCREMENT;
        dma_init.MemoryOrM2MDstIncMode = LL_DMA_MEMORY_INCREMENT;
        dma_init.PeriphOrM2MSrcDataSize = LL_DMA_PDATAALIGN_BYTE;
        dma_init.MemoryOrM2MDstDataSize = LL_DMA_MDATAALIGN_BYTE;
        dma_init.NbData = sizeof(usart_mem);
        dma_init.Priority = LL_DMA_PRIORITY_MEDIUM;
#if defined(LWGSM_USART_DMA_RX_STREAM)
        LL_DMA_Init(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM, &dma_init);
#else
        LL_DMA_Init(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH, &dma_init);
#endif /* defined(LWGSM_USART_DMA_RX_STREAM) */

        /* Enable DMA interrupts */
#if defined(LWGSM_USART_DMA_RX_STREAM)
        LL_DMA_EnableIT_HT(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
        LL_DMA_EnableIT_TC(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
        LL_DMA_EnableIT_TE(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
        LL_DMA_EnableIT_FE(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
        LL_DMA_EnableIT_DME(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
#else
        LL_DMA_EnableIT_HT(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
        LL_DMA_EnableIT_TC(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
        LL_DMA_EnableIT_TE(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
#endif /* defined(LWGSM_USART_DMA_RX_STREAM) */

        /* Enable DMA interrupts */
        NVIC_SetPriority(LWGSM_USART_DMA_RX_IRQ, NVIC_EncodePriority(NVIC_GetPriorityGrouping(), 0x07, 0x00));
        NVIC_EnableIRQ(LWGSM_USART_DMA_RX_IRQ);

        old_pos = 0;
        is_running = 1;

        /* Start DMA and USART */
#if defined(LWGSM_USART_DMA_RX_STREAM)
        LL_DMA_EnableStream(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_STREAM);
#else
        LL_DMA_EnableChannel(LWGSM_USART_DMA, LWGSM_USART_DMA_RX_CH);
#endif /* defined(LWGSM_USART_DMA_RX_STREAM) */
        LL_USART_Enable(LWGSM_USART);
    } else {
        osDelay(10);
        LL_USART_Disable(LWGSM_USART);
        usart_init.BaudRate = baudrate;
        LL_USART_Init(LWGSM_USART, &usart_init);
        LL_USART_Enable(LWGSM_USART);
    }

    /* Create mbox and start thread */
    if (usart_ll_mbox_id == NULL) {
        usart_ll_mbox_id = osMessageQueueNew(10, sizeof(void*), NULL);
    }
    if (usart_ll_thread_id == NULL) {
        const osThreadAttr_t attr = {
            .stack_size = 1024
        };
        usart_ll_thread_id = osThreadNew(usart_ll_thread, usart_ll_mbox_id, &attr);
    }
}

#if defined(LWGSM_RESET_PIN)
/**
 * \brief           Hardware reset callback
 */
static uint8_t
reset_device(uint8_t state) {
    if (state) {                                /* Activate reset line */
        LL_GPIO_ResetOutputPin(LWGSM_RESET_PORT, LWGSM_RESET_PIN);
    } else {
        LL_GPIO_SetOutputPin(LWGSM_RESET_PORT, LWGSM_RESET_PIN);
    }
    return 1;
}
#endif /* defined(LWGSM_RESET_PIN) */

/**
 * \brief           Send data to GSM device
 * \param[in]       data: Pointer to data to send
 * \param[in]       len: Number of bytes to send
 * \return          Number of bytes sent
 */
static size_t
send_data(const void* data, size_t len) {
    const uint8_t* d = data;

    for (size_t i = 0; i < len; ++i, ++d) {
        LL_USART_TransmitData8(LWGSM_USART, *d);
        while (!LL_USART_IsActiveFlag_TXE(LWGSM_USART)) {}
    }
    return len;
}

/**
 * \brief           Callback function called from initialization process
 * \note            This function may be called multiple times if AT baudrate is changed from application
 * \param[in,out]   ll: Pointer to \ref lwgsm_ll_t structure to fill data for communication functions
 * \param[in]       baudrate: Baudrate to use on AT port
 * \return          Member of \ref lwgsmr_t enumeration
 */
lwgsmr_t
lwgsm_ll_init(lwgsm_ll_t* ll) {
#if !LWGSM_CFG_MEM_CUSTOM
    static uint8_t memory[LWGSM_MEM_SIZE];
    lwgsm_mem_region_t mem_regions[] = {
        { memory, sizeof(memory) }
    };

    if (!initialized) {
        lwgsm_mem_assignmemory(mem_regions, LWGSM_ARRAYSIZE(mem_regions));  /* Assign memory for allocations */
    }
#endif /* !LWGSM_CFG_MEM_CUSTOM */

    if (!initialized) {
        ll->send_fn = send_data;                /* Set callback function to send data */
#if defined(LWGSM_RESET_PIN)
        ll->reset_fn = reset_device;            /* Set callback for hardware reset */
#endif /* defined(LWGSM_RESET_PIN) */
    }

    configure_uart(ll->uart.baudrate);          /* Initialize UART for communication */
    initialized = 1;
    return lwgsmOK;
}

/**
 * \brief           Callback function to de-init low-level communication part
 * \param[in,out]   ll: Pointer to \ref lwgsm_ll_t structure to fill data for communication functions
 * \return          \ref lwgsmOK on success, member of \ref lwgsmr_t enumeration otherwise
 */
lwgsmr_t
lwgsm_ll_deinit(lwgsm_ll_t* ll) {
    if (usart_ll_mbox_id != NULL) {
        osMessageQueueId_t tmp = usart_ll_mbox_id;
        usart_ll_mbox_id = NULL;
        osMessageQueueDelete(tmp);
    }
    if (usart_ll_thread_id != NULL) {
        osThreadId_t tmp = usart_ll_thread_id;
        usart_ll_thread_id = NULL;
        osThreadTerminate(tmp);
    }
    initialized = 0;
    LWGSM_UNUSED(ll);
    return lwgsmOK;
}

/**
 * \brief           UART global interrupt handler
 */
void
LWGSM_USART_IRQHANDLER(void) {
    LL_USART_ClearFlag_IDLE(LWGSM_USART);
    LL_USART_ClearFlag_PE(LWGSM_USART);
    LL_USART_ClearFlag_FE(LWGSM_USART);
    LL_USART_ClearFlag_ORE(LWGSM_USART);
    LL_USART_ClearFlag_NE(LWGSM_USART);

    if (usart_ll_mbox_id != NULL) {
        void* d = (void*)1;
        osMessageQueuePut(usart_ll_mbox_id, &d, 0, 0);
    }
}

/**
 * \brief           UART DMA stream/channel handler
 */
void
LWGSM_USART_DMA_RX_IRQHANDLER(void) {
    LWGSM_USART_DMA_RX_CLEAR_TC;
    LWGSM_USART_DMA_RX_CLEAR_HT;

    if (usart_ll_mbox_id != NULL) {
        void* d = (void*)1;
        osMessageQueuePut(usart_ll_mbox_id, &d, 0, 0);
    }
}

#endif /* !__DOXYGEN__ */
