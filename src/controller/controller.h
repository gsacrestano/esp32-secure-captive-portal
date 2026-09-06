/**
 * @file controller.h
 * @brief System controller lifecycle management.
 */

#pragma once

namespace controller
{
    /**
     * @brief Initializes and starts controller services.
     * @return True if successfully started, false otherwise.
     */
    bool begin();

    /**
     * @brief Stops controller services and releases resources.
     * @return True if successfully stopped, false otherwise.
     */
    bool stop();
}