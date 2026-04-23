# MITRE Caldera™ for OT plugin: GEMS

A [MITRE Caldera™ for OT](https://github.com/mitre/caldera-ot) plugin
supplying [Caldera](https://github.com/mitre/caldera) with Ground Equipment
Monitoring Service (GEMS) Protocol TTPs mapped to [MITRE ATT&CK® for ICS](https://attack.mitre.org/matrices/ics/). This
is part of a series of plugins that provide added threat emulation capability
for Operational Technology (OT) environments. 

Full plugin [documentation](docs/gems.md) can be viewed as part of
fieldmanual, once the Caldera server is running. 

## Installation

To run Caldera along with the GEMS plugin:
1. Download Caldera as detailed in the [Installation Guide](https://github.com/mitre/caldera)
2. Install the GEMS plugin in Caldera's plugin directory: `caldera/plugins`
3. Enable the GEMS plugin by adding `- gems` to the list of enabled plugins in
   `conf/local.yml` or `conf/default.yml` (if running Caldera in insecure mode)

## Usage

1. **Select Your Target System**  
   Determine the system you want to communicate with via the GEMS protocol.

2. **Choose a Host for the Caldera Agent**  
   Identify a suitable machine to host the Caldera agent. This machine will act
   as the intermediary, sending GEMS messages to your target system. Ensure the
   host has network access to the target system and meets the deployment
   requirements.

3. **Deploy the Caldera Agent**  
   Deploy the Caldera agent to the chosen host. Instructions and scripts to 
   acheive this are found on the Caldera server GUI on the "Agents" page. 

4. **Execute GEMS Plugin Abilities**  
   Utilize the GEMS plugin's abilities to perform specific actions on the
   target system. Combine abilities such as reading parameters and calling 
   directives to achieve your desired outcome.

For detailed instructions and ability descriptions, see the
[fieldmanual documention](/docs/gems.md#usage).

### Payload Compatibility

This plugin uses pre-compiled binaries (payloads) that are delivered and
executed on the target device by the Caldera agent. To execute, the payloads 
must be compatible with the target device operating system. For more information 
on compatibility, see the [fieldmanual documention](/docs/gems.md#payloads) and 
the [source README](/src/README.md). 

### Plugin Payload Source Code
For additional information on the GEMS plugin payload source code, please see
the [source README](/src/README.md).
