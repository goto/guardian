module.exports = {
  docsSidebar: [
    'introduction',
    'installation',
    'roadmap',
    {
      type: "category",
      label: "Tour",
      items: [
        "tour/introduction",
        "tour/configuration",
        "tour/create-policy",
        "tour/create-provider",
        "tour/update-resource",
        "tour/create-appeal",
        "tour/approve-reject-appeal",
        "tour/complex-use-case",
      ],
    },
    {
      type: "category",
      label: "Concepts",
      items: [
        "concepts/overview",
        "concepts/architecture",
      ],
    },
    {
      type: "category",
      label: "Guides",
      items: [
        "guides/deployment",
      ],
    },
    {
      type: "category",
      label: "Providers",
      items: [
        "providers/bigquery",
        "providers/gcloud_iam",
        "providers/gcs",
        "providers/grafana",
        "providers/metabase",
        "providers/noop",
        "providers/tableau",
      ],
    },
    {
      type: "category",
      label: "Reference",
      items: [
        "reference/api",
        "reference/cli",
        "reference/appeal",
        "reference/policy",
        "reference/provider",
        "reference/resource",
        "reference/jobs",
        "reference/glossary",
        "reference/configuration",
      ],
    },
    {
      type: "category",
      label: "Extend",
      items: [
        "contribute/provider",
      ]
    },
    {
      type: "category",
      label: "Contribute",
      items: [
        "contribute/architecture",
        "contribute/contribution",
      ],
    },
  ],
};