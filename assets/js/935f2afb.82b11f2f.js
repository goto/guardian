"use strict";(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[53],{1109:function(e){e.exports=JSON.parse('{"pluginId":"default","version":"current","label":"Next","banner":null,"badge":false,"className":"docs-version-current","isLast":true,"docsSidebars":{"docsSidebar":[{"type":"link","label":"Introduction","href":"/guardian/docs/introduction","docId":"introduction"},{"type":"link","label":"Installation","href":"/guardian/docs/installation","docId":"installation"},{"type":"link","label":"Roadmap","href":"/guardian/docs/roadmap","docId":"roadmap"},{"type":"category","label":"Concepts","items":[{"type":"link","label":"Overview","href":"/guardian/docs/concepts/overview","docId":"concepts/overview"}],"collapsed":true,"collapsible":true},{"type":"category","label":"Tour","items":[{"type":"link","label":"Introduction","href":"/guardian/docs/tour/introduction","docId":"tour/introduction"},{"type":"link","label":"Configure client","href":"/guardian/docs/tour/configuration","docId":"tour/configuration"},{"type":"link","label":"Create a policy","href":"/guardian/docs/tour/create-policy","docId":"tour/create-policy"},{"type":"link","label":"Create a provider","href":"/guardian/docs/tour/create-provider","docId":"tour/create-provider"},{"type":"link","label":"Update resource","href":"/guardian/docs/tour/update-resource","docId":"tour/update-resource"},{"type":"link","label":"Create an appeal","href":"/guardian/docs/tour/create-appeal","docId":"tour/create-appeal"},{"type":"link","label":"Manage appeal","href":"/guardian/docs/tour/approve-reject-appeal","docId":"tour/approve-reject-appeal"},{"type":"link","label":"Update policy rules","href":"/guardian/docs/tour/complex-use-case","docId":"tour/complex-use-case"}],"collapsed":true,"collapsible":true},{"type":"category","label":"Providers","items":[{"type":"link","label":"Big Query","href":"/guardian/docs/providers/bigquery","docId":"providers/bigquery"},{"type":"link","label":"GCP","href":"/guardian/docs/providers/gcloud_iam","docId":"providers/gcloud_iam"},{"type":"link","label":"GCS","href":"/guardian/docs/providers/gcs","docId":"providers/gcs"},{"type":"link","label":"Grafana","href":"/guardian/docs/providers/grafana","docId":"providers/grafana"},{"type":"link","label":"Metabase","href":"/guardian/docs/providers/metabase","docId":"providers/metabase"},{"type":"link","label":"No Op","href":"/guardian/docs/providers/noop","docId":"providers/noop"},{"type":"link","label":"Tableau","href":"/guardian/docs/providers/tableau","docId":"providers/tableau"}],"collapsed":true,"collapsible":true},{"type":"category","label":"Reference","items":[{"type":"link","label":"API","href":"/guardian/docs/reference/api","docId":"reference/api"},{"type":"link","label":"CLI","href":"/guardian/docs/reference/cli","docId":"reference/cli"},{"type":"link","label":"Appeal","href":"/guardian/docs/reference/appeal","docId":"reference/appeal"},{"type":"link","label":"Policy","href":"/guardian/docs/reference/policy","docId":"reference/policy"},{"type":"link","label":"Provider","href":"/guardian/docs/reference/provider","docId":"reference/provider"},{"type":"link","label":"Resource","href":"/guardian/docs/reference/resource","docId":"reference/resource"},{"type":"link","label":"Jobs","href":"/guardian/docs/reference/jobs","docId":"reference/jobs"},{"type":"link","label":"Glossary","href":"/guardian/docs/reference/glossary","docId":"reference/glossary"}],"collapsed":true,"collapsible":true},{"type":"category","label":"Contribute","items":[{"type":"link","label":"Architecture","href":"/guardian/docs/contribute/architecture","docId":"contribute/architecture"},{"type":"link","label":"Contribution Process","href":"/guardian/docs/contribute/contribution","docId":"contribute/contribution"},{"type":"link","label":"Development Guide","href":"/guardian/docs/contribute/development","docId":"contribute/development"}],"collapsed":true,"collapsible":true}]},"docs":{"concepts/overview":{"id":"concepts/overview","title":"Overview","description":"The following topics contains an overview of the importatnt concepts related to the Guardian tool.","sidebar":"docsSidebar"},"contribute/architecture":{"id":"contribute/architecture","title":"Architecture","description":"Basic building blocks of Guardian are","sidebar":"docsSidebar"},"contribute/contribution":{"id":"contribute/contribution","title":"Contribution Process","description":"The following is a set of guidelines for contributing to Guardian. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request. Here are some important resources:","sidebar":"docsSidebar"},"contribute/development":{"id":"contribute/development","title":"Development Guide","description":"","sidebar":"docsSidebar"},"installation":{"id":"installation","title":"Installation","description":"There are several approaches to install Guardian CLI","sidebar":"docsSidebar"},"introduction":{"id":"introduction","title":"Introduction","description":"Welcome to the introductory guide to Guardian! This guide is the best place to start with Guardian. We cover what Guardian is, what problems it can solve, how it works, and how you can get started using it. If you are familiar with the basics of Guardian, the guide provides a more detailed reference of available features.","sidebar":"docsSidebar"},"providers/bigquery":{"id":"providers/bigquery","title":"Big Query","description":"BigQuery is an enterprise data warehouse tool for storing and querying massive datasets with super-fast SQL queries using the processing power of Google\'s infrastructure.","sidebar":"docsSidebar"},"providers/gcloud_iam":{"id":"providers/gcloud_iam","title":"GCP","description":"GCloud IAM provides a simple and consistent access control interface for all Google Cloud services. The Cloud IAM lets administrators authorize who can take action on specific resources, giving you full control and visibility to manage Google Cloud resources centrally.","sidebar":"docsSidebar"},"providers/gcs":{"id":"providers/gcs","title":"GCS","description":"Google Cloud Storage(in short GCS) is the object storage service offered by Google Cloud. GCS has distinct namespaces called Buckets that each one contains multiple Objects which are used for storing the data.","sidebar":"docsSidebar"},"providers/grafana":{"id":"providers/grafana","title":"Grafana","description":"Grafana is open source visualization and analytics software. It allows you to query, visualize, alert on, and explore your metrics no matter where they are stored. In plain English, it provides you with tools to turn your time-series database \\\\(TSDB\\\\) data into beautiful graphs and visualizations.","sidebar":"docsSidebar"},"providers/metabase":{"id":"providers/metabase","title":"Metabase","description":"Metabase is a data visualization tool that lets you connect to external databases and create charts and dashboards based on the data from the databases. Guardian supports access management to the following resources in Metabase:","sidebar":"docsSidebar"},"providers/noop":{"id":"providers/noop","title":"No Op","description":"Using a No-op provider, Guardian users can take advantage of policy workflow without adding resources to this provider in Guardian. Users can call the Guardian APIs for approval workflows and appeal management. This can also allow users to locally test Guardian easily without configuring an actual provider.","sidebar":"docsSidebar"},"providers/tableau":{"id":"providers/tableau","title":"Tableau","description":"Tableau empowers everyone to see and understand the data. It is business intelligent for an entire organization. We can connect to any data source, be it a spreadsheet, database or bigdata. We can access data warehouses or cloud data as well.","sidebar":"docsSidebar"},"reference/api":{"id":"reference/api","title":"API","description":"Managing Policies","sidebar":"docsSidebar"},"reference/appeal":{"id":"reference/appeal","title":"Appeal","description":"JSON Representation","sidebar":"docsSidebar"},"reference/cli":{"id":"reference/cli","title":"CLI","description":"Guardian is a command line tool used to interact with the main guardian service. Follow the installation and configuration guides to set up the CLI tool for Guardian.","sidebar":"docsSidebar"},"reference/glossary":{"id":"reference/glossary","title":"Glossary","description":"Policy:* Configurable approval flow for request approval","sidebar":"docsSidebar"},"reference/jobs":{"id":"reference/jobs","title":"Jobs","description":"Server Jobs Configurations","sidebar":"docsSidebar"},"reference/policy":{"id":"reference/policy","title":"Policy","description":"YAML Representation","sidebar":"docsSidebar"},"reference/provider":{"id":"reference/provider","title":"Provider","description":"A provider configuration is required when we want to register a provider instance to Guardian.","sidebar":"docsSidebar"},"reference/resource":{"id":"reference/resource","title":"Resource","description":"JSON Representation","sidebar":"docsSidebar"},"roadmap":{"id":"roadmap","title":"Roadmap","description":"In the following section, you can learn about what features we\'re working on, what stage they\'re in, and when we expect to bring them to you. Have any questions or comments about items on the roadmap? Join the discussions on the Gaurdian Github forum.","sidebar":"docsSidebar"},"support":{"id":"support","title":"Need help?","description":"Need a bit of help? We\'re here for you. Check out our current issues, GitHub discussions, or get support through Slack."},"tour/approve-reject-appeal":{"id":"tour/approve-reject-appeal","title":"Manage appeal","description":"Note: Approve/reject still not supported from the CLI currently.","sidebar":"docsSidebar"},"tour/complex-use-case":{"id":"tour/complex-use-case","title":"Update policy rules","description":"In this example we will explain some more details around the policy configuartions. Guardian can connect to an external identity manager to retrieve user details information. When a user creates an appeal using the policy given below, Guardian will connect to http://youridentitymanager.com/api/users/ for taking the user information defined in the iam_schema within the policy.","sidebar":"docsSidebar"},"tour/configuration":{"id":"tour/configuration","title":"Configure client","description":"Guardian binary contains both the CLI client and the server itself. Each has it\'s own configuration in order to run. Server configuration contains information such as database credentials, log severity, etc. while CLI client configuration only has configuration about which server to connect.","sidebar":"docsSidebar"},"tour/create-appeal":{"id":"tour/create-appeal","title":"Create an appeal","description":"Note:","sidebar":"docsSidebar"},"tour/create-policy":{"id":"tour/create-policy","title":"Create a policy","description":"Pre-Requisites","sidebar":"docsSidebar"},"tour/create-provider":{"id":"tour/create-provider","title":"Create a provider","description":"We are going to register a Google Cloud Bigquery provider with a dataset named Playground in this example.","sidebar":"docsSidebar"},"tour/introduction":{"id":"tour/introduction","title":"Introduction","description":"This tour introduces you to Guardian. Along the way you will learn how to manage create policies, resources and manage appeals.","sidebar":"docsSidebar"},"tour/update-resource":{"id":"tour/update-resource","title":"Update resource","description":"We will try to update a resource information in this example exercise. Let\'s say we want to add owner\'s information to the playground dataset.","sidebar":"docsSidebar"}}}')}}]);