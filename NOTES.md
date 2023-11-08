<b>Loss accuracy</b>

In general, dpinger works a bit differently than other latency monitors. Rather than a "probe" that fires off and processes a handful of echo request/replies all at once, dpinger maintains a rolling array of echo requests spaced on the send interval. In other words, instead of waking up every second and sending 4 echo requests at once, dpinger sends an echo request every 250 milliseconds. When dpinger receives an echo reply, the time difference between the request packet and reply packet (latency) is recorded. There is nothing that times out an echo request/reply and records it as permanently lost.

When the alert check is made, or a report is generated, dpinger goes through the array and examines each echo request. If a reply has been received, it is used as part of the overall latency calculation. If a reply has not yet been received, the amount of time since the request is compared against the loss interval. If it is greater than the loss interval, the request/reply is counted as lost in the current report. However the concept of the request/reply being lost is not a permanent decision. In subsequent reports, if a the missing reply has been received, its latency will be used instead of being counted as lost.

It's important to keep in mind that latency and loss are reported as averages across the entire request set. The default time period for dpinger is 60 seconds, with an echo request being sent every 500 milliseconds. This means that the latency and loss will be reported as averages across 116-120 samples. The alert check runs every second by default. So each time, the 4 oldest entries in the set have been replaced by the 4 newest ones.

Note that if you want accurate loss reporting, it is important that the number of samples be sufficient. In order to achieve 1% loss resolution, you have need more than 100 samples in the set. The calculation for loss resolution is:

  100 / ((time_period - loss_interval) / send_interval)

The default settings for dpinger report loss with an accuracy of 0.87%.
