# Domain Monitor

Domain Monitor is a Go application designed to monitor the WHOIS information and DNS records of domains at a specified interval. It sends notifications to various webhooks (PagerDuty, Microsoft Teams, Discord) if there are any changes in the domain information. The tool supports YAML configuration for specifying domains, webhooks, and monitoring intervals.

## Features
- Monitors WHOIS information and DNS records for a list of domains.
- Supports notifications via PagerDuty, Microsoft Teams, and Discord webhooks.
- Configurable monitoring interval (minimum 5 minutes).
- Sends notifications on enabling monitoring, changes in domain information, and stopping monitoring.

## Table of Contents
- [Installation](#installation)
- [Configuration](#configuration)
- [Example Configuration](#example-configuration)
- [Usage](#usage)
- [Notifications](#notifications)
- [Development](#development)  


## Installation1.  **Clone the Repository**

```bash
git  clone  https://github.com/yourusername/domain-monitor.git
cd  domain-monitor
``` 

1.  **Install Dependencies**

Ensure you have Go installed. Then, install the required Go packages:  

```bash
go  get  github.com/likexian/whois
go  get  github.com/likexian/whois-parser
go  get  gopkg.in/yaml.v2
```

1.  **Build the Application**

Build the Go application:
```bash
go  build  -o  domain-monitor  main.go
```

## Configuration
The configuration file (`config.yaml`) specifies the domains to monitor, webhooks to send notifications to, and the monitoring interval.

### Example Configuration
Create a `config.yaml` file in the root directory of the project with the following structure:

```yaml
interval: 5
domains:
- name: example.com
# webhooks:
# - type: teams
# url: "https://outlook.office.com/webhook/..."
webhooks:
- type: discord
url: "https://discord.com/api/webhooks/...."
```

-  `interval`: The monitoring interval in minutes. The minimum interval is 5 minutes.
-  `domains`: A list of domains to monitor. Each domain can have its own set of webhooks.
-  `webhooks`: A list of webhooks to send notifications to for all domains.

## Usage  
1.  **Run the Application**
Ensure `config.yaml` is properly configured, then run the application:
```
./domain-monitor
```
1.  **Monitor the Logs**
The application will output logs indicating the status of the monitoring process, including any errors encountered during WHOIS lookups, DNS resolutions, or webhook notifications.

## Notifications
The application sends notifications to the configured webhooks in the following cases:
-  **Monitoring Enabled**: When monitoring starts for a domain.
-  **Domain Information Changed**: When there is a change in the WHOIS information or DNS records of a domain.
-  **Monitoring Finished**: When a domain is removed from the configuration file and monitoring stops.


### Discord Webhooks
Discord notifications are sent as rich embeds with the following structure:
-  **Title**: A brief description of the event (e.g., "Monitoring enabled for domain: example.com").
-  **Description**: Detailed information about the domain, including WHOIS and DNS details.
-  **Color**: The embed color (set to blue in this example).  

## Development
To contribute to the development of this project:

1.  **Fork the Repository**

Fork the repository on GitHub and clone your fork locally. 

1.  **Create a Branch**
Create a new branch for your feature or bugfix:

```
git checkout -b my-feature-branch
```

1.  **Make Changes**
Make your changes, ensuring to update tests and documentation as necessary.

1.  **Commit and Push**
Commit your changes and push them to your fork:  

```
git add .
git commit -m "Description of your changes"
git push origin my-feature-branch
```

1.  **Create a Pull Request**
Open a pull request on GitHub, describing the changes you have made and why they should be merged.

