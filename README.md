# Chickadee

Chickadee is a tiny network scan detector written in Go, designed to run as a service on Windows systems.

It features the ability to send alerts via SMTP. Additionally, it also logs to the Windows Application Event Log, so if you're using a collector on that endpoint, you can monitor the below event IDs and create alerts based on them.

<table>
    <thead>
        <th>Event ID</th>
        <th>Description</th>
    </thead>
    <tbody>
        <tr>
            <td>500</td>
            <td>Application Crash</td>
        </tr>
        <tr>
            <td>501</td>
            <td>Starting Service</td>
        </tr>
        <tr>
            <td>502</td>
            <td>Stopping Service</td>
        </tr>
        <tr>
            <td>503</td>
            <td>Generic Warning</td>
        </tr>
        <tr>
            <td>510</td>
            <td>Generic Info</td>
        </tr>
        <tr>
            <td>511</td>
            <td>Detector Initiated</td>
        </tr>
        <tr>
            <td>515</td>
            <td>Network Scan Detected</td>
        </tr>
    </tbody>
</table>

## Installation

On 64-bit Windows systems, just run the latest installer from the Releases tab of this repository

## Configuration

The configuration file for chickadee can be located at:

`C:\Program Files\Chickadee\config.ini`

Any changes in this document require the service `chickadee` to be restarted.

In the config, you can edit detection parameters, the endpoint's friendly name to include with alerts, SMTP Auth/TLS settings, and SMTP recipients. Currently, SMTP only supports a single recipient; this will be changing soon.

## Coming Soon

Some features that are planned to be added:

- SNMP Trap Alerting
- Webhook Alerting
- Configurable Whitelisted IPs
- More alert details

## Contribute

If you like this software, and you can program in Go, feel free to fork this repo and make a PR. I'm new to Go so I'm sure there are a lot of rookie mistake I've made.