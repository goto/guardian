"use strict";(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[15],{3905:function(e,t,a){a.d(t,{Zo:function(){return p},kt:function(){return c}});var n=a(7294);function r(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function i(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function o(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?i(Object(a),!0).forEach((function(t){r(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):i(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,n,r=function(e,t){if(null==e)return{};var a,n,r={},i=Object.keys(e);for(n=0;n<i.length;n++)a=i[n],t.indexOf(a)>=0||(r[a]=e[a]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)a=i[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(r[a]=e[a])}return r}var s=n.createContext({}),d=function(e){var t=n.useContext(s),a=t;return e&&(a="function"==typeof e?e(t):o(o({},t),e)),a},p=function(e){var t=d(e.components);return n.createElement(s.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},u=n.forwardRef((function(e,t){var a=e.components,r=e.mdxType,i=e.originalType,s=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),u=d(a),c=r,k=u["".concat(s,".").concat(c)]||u[c]||m[c]||i;return a?n.createElement(k,o(o({ref:t},p),{},{components:a})):n.createElement(k,o({ref:t},p))}));function c(e,t){var a=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=a.length,o=new Array(i);o[0]=u;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:r,o[1]=l;for(var d=2;d<i;d++)o[d]=a[d];return n.createElement.apply(null,o)}return n.createElement.apply(null,a)}u.displayName="MDXCreateElement"},4228:function(e,t,a){a.r(t),a.d(t,{assets:function(){return s},contentTitle:function(){return o},default:function(){return m},frontMatter:function(){return i},metadata:function(){return l},toc:function(){return d}});var n=a(3117),r=(a(7294),a(3905));const i={},o="Tableau",l={unversionedId:"providers/tableau",id:"providers/tableau",title:"Tableau",description:"Tableau empowers everyone to see and understand the data. It is business intelligent for an entire organization. We can connect to any data source, be it a spreadsheet, database or bigdata. We can access data warehouses or cloud data as well.",source:"@site/docs/providers/tableau.md",sourceDirName:"providers",slug:"/providers/tableau",permalink:"/guardian/docs/providers/tableau",draft:!1,editUrl:"https://github.com/odpf/guardian/edit/master/docs/docs/providers/tableau.md",tags:[],version:"current",frontMatter:{},sidebar:"docsSidebar",previous:{title:"No Op",permalink:"/guardian/docs/providers/noop"},next:{title:"API",permalink:"/guardian/docs/reference/api"}},s={},d=[{value:"Tableau resources",id:"tableau-resources",level:3},{value:"Tableau Users",id:"tableau-users",level:3},{value:"Authentication",id:"authentication",level:2},{value:"Access Management",id:"access-management",level:2},{value:"Config Example",id:"config-example",level:4},{value:"Tableau Credentials",id:"tableau-credentials",level:2},{value:"Tableau Resource Type",id:"tableau-resource-type",level:2},{value:"Tableau Permissions",id:"tableau-permissions",level:2},{value:"Table Resource Permission",id:"table-resource-permission",level:2}],p={toc:d};function m(e){let{components:t,...a}=e;return(0,r.kt)("wrapper",(0,n.Z)({},p,a,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"tableau"},"Tableau"),(0,r.kt)("p",null,"Tableau empowers everyone to see and understand the data. It is business intelligent for an entire organization. We can connect to any data source, be it a spreadsheet, database or bigdata. We can access data warehouses or cloud data as well."),(0,r.kt)("h3",{id:"tableau-resources"},"Tableau resources"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Sites")," In Tableau-speak, we use site to mean a collection of users, groups, and content ","(","workbooks, data sources",")"," that\u2019s walled off from any other groups and content on the same instance of Tableau Server. Another way to say this is that Tableau Server supports multi-tenancy by allowing server administrators to create sites on the server for multiple sets of users and content. All server content is published, accessed, and managed on a per-site basis. Each site has its own URL and its own set of users ","(","although each server user can be added to multiple sites",")",". Each site\u2019s content ","(","projects, workbooks, and data sources",")"," is completely segregated from content on other sites."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Projects")," act as folder in tableau. A content resource ","(","workbooks and data sources",")"," can live in only project."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Workbooks")," in tableau are a collection of views, metrics and data sources. Guardian supports access at all the levels i.e. workbook, metrics and data sources. Workbooks have options to show or hide tabs. If it is shown, permissions to the resources below are only ",(0,r.kt)("strong",{parentName:"li"},"inherited")," from the workbook level. If it is hidden, permissions can be given at the view/metric/data source level."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Views")," are a visualization or viz that you create in Tableau. A viz might be a chart, a graph, a map, a plot, or even a text table. Access can be granted at view level only if the parent workbook has tabs option set to hidden."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Metrics")," are new type of content that is fully integrated with Tableau's data and analytics platform through Tableau Server and Tableau Online. Metrics update automatically and display the most recent value. Access can be granted at metric level only if the parent workbook has tabs option set to hidden."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Data Sources")," can be published to Tableau Server when your Tableau users want to share data connections they\u2019ve defined. When a data source is published to the server, other users can connect to it from their own workbooks, as they do other types of data. When the data in the Tableau data source is updated, all workbooks that connect to it pick up the changes. Access can be granted at data source level only if the parent workbook has tabs option set to hidden."),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("strong",{parentName:"li"},"Flows")," are created to schedule tasks to run at a specific time or on a recurring basis. Access can be directly granted at a flow level.")),(0,r.kt)("h3",{id:"tableau-users"},"Tableau Users"),(0,r.kt)("p",null,"Tableau allows to group users into groups and manage group level access to the resources. But, Guardian allows direct user level access to any resource."),(0,r.kt)("h2",{id:"authentication"},"Authentication"),(0,r.kt)("p",null,"Guardian requires ",(0,r.kt)("strong",{parentName:"p"},"host"),", ",(0,r.kt)("strong",{parentName:"p"},"email"),", ",(0,r.kt)("strong",{parentName:"p"},"password")," and ",(0,r.kt)("strong",{parentName:"p"},"content url")," of an administrator user in Tableau."),(0,r.kt)("p",null,"Example provider config for tableau:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},"\n---\ncredentials:\n  host: https://prod-apnortheast-a.online.tableau.com\n  username: user@test.com\n  password: password@123\n  content_url: guardiantestsite\n")),(0,r.kt)("h2",{id:"access-management"},"Access Management"),(0,r.kt)("p",null,"In Guardian, user access can be given at the workbook, views, metrics, data sources or flow level."),(0,r.kt)("h4",{id:"config-example"},"Config Example"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},"type: tableau\nurn: 691acb66-27ef-4b4f-9222-f07052e6ffd0\nlabels:\n  entity: gojek\n  landscape: id\ncredentials:\n  host: https://prod-apnortheast-a.online.tableau.com\n  username: test@email.com\n  password: password@123\n  content_url: guardiantestsite\nappeal:\n  allow_active_access_extension_in: 7d\nresources:\n  - type: workbook\n    policy:\n      id: policy_1\n      version: 1\n    roles:\n      - id: read\n        name: Read\n        permissions:\n          - name: Read:Allow\n          - name: ViewComments:Allow\n          - name: ViewUnderlyingData:Allow\n          - name: Filter:Allow\n          - name: Viewer\n            type: site_role\n      - id: write\n        name: Write\n        permissions:\n          - name: Write:Allow\n          - name: AddComment:Allow\n          - name: Creator\n            type: site_role\n      - id: admin\n        name: Admin\n        permissions:\n          - name: ChangeHierarchy:Allow\n          - name: ChangePermissions:Allow\n          - name: Delete:Allow\n          - name: ServerAdministrator\n            type: site_role\n      - id: export\n        name: Export\n        permissions:\n          - name: ExportData:Allow\n          - name: ExportImage:Allow\n          - name: ExportXml:Allow\n          - name: SiteAdministratorExplorer\n            type: site_role\n      - id: other\n        name: Other\n        permissions:\n          - name: ShareView:Allow\n          - name: WebAuthoring:Allow\n          - name: ExplorerCanPublish\n            type: site_role\n  - type: flow\n    policy:\n      id: policy_2\n      version: 1\n    roles:\n      - id: read\n        name: Read\n        permissions:\n          - name: Read:Allow\n          - name: Viewer\n            type: site_role\n      - id: write\n        name: Write\n        permissions:\n          - name: Write:Allow\n          - name: Creator\n            type: site_role\n      - id: admin\n        name: Admin\n        permissions:\n          - name: ChangeHierarchy:Allow\n          - name: ChangePermissions:Allow\n          - name: Delete:Allow\n          - name: ServerAdministrator\n            type: site_role\n      - id: export\n        name: Export\n        permissions:\n          - name: ExportXml:Allow\n          - name: SiteAdministratorExplorer\n            type: site_role\n      - id: other\n        name: Other\n        permissions:\n          - name: Execute:Allow\n          - name: ExplorerCanPublish\n            type: site_role\n")),(0,r.kt)("h2",{id:"tableau-credentials"},"Tableau Credentials"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:"left"},"Fields"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Deatils"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"host")),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")," Required. Tableau instance host. Example: ",(0,r.kt)("inlineCode",{parentName:"td"},"https://prod-apnortheast-a.online.tableau.com"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"username")),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"email")," Required. Email address of an account that has Administration permission.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"password")),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")," Required. Account's password.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"content_url")),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")," Required. Site's content url aka slug. Example: In ",(0,r.kt)("inlineCode",{parentName:"td"},"https://10ay.online.tableau.com/#/site/MarketingTeam/workbooks")," the content url is ",(0,r.kt)("inlineCode",{parentName:"td"},"MarketingTeam"))))),(0,r.kt)("h2",{id:"tableau-resource-type"},"Tableau Resource Type"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Workbook")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"View")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Metric")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Data Source")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"Flow"))),(0,r.kt)("h2",{id:"tableau-permissions"},"Tableau Permissions"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:"left"},"Fields"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Permissions"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"Workbook")),(0,r.kt)("td",{parentName:"tr",align:"left"},"AddComment, ChangeHierarchy, ChangePermissions, Delete, ExportData, ExportImage, ExportXml, Filter, Read ","(","view",")",", ShareView, ViewComments, ViewUnderlyingData, WebAuthoring, and Write.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"View")),(0,r.kt)("td",{parentName:"tr",align:"left"},"AddComment, ChangePermissions, Delete, ExportData, ExportImage, ExportXml, Filter, Read ","(","view",")",", ShareView, ViewComments, ViewUnderlyingData, WebAuthoring, and Write.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"Metric")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Read, Write, Delete, ChangeHierarchy, ChangePermissions.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"Data Source")),(0,r.kt)("td",{parentName:"tr",align:"left"},"ChangePermissions, Connect, Delete, ExportXml, Read ","(","view",")",", and Write.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"Flow")),(0,r.kt)("td",{parentName:"tr",align:"left"},"ChangeHierarchy, ChangePermissions, Delete, Execute, ExportXml ","(","Download",")",", Read ","(","view",")",", and Write.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"Site Roles")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Creator, Explorer, ExplorerCanPublish, ServerAdministrator, SiteAdministratorExplorer, SiteAdministratorCreator, Unlicensed, Read only, or Viewer.")))),(0,r.kt)("h2",{id:"table-resource-permission"},"Table Resource Permission"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:"left"},"Fields"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Type"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Details"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"urn")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Required. ",(0,r.kt)("inlineCode",{parentName:"td"},"string")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Tableau Site Id.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"resources: type")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Required. ",(0,r.kt)("inlineCode",{parentName:"td"},"string")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Must be one of ",(0,r.kt)("inlineCode",{parentName:"td"},"workbook, view, metric, datasource and flow"),".")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"resources: policy")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Required. ",(0,r.kt)("inlineCode",{parentName:"td"},"string & string")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Must have id as policy name. Must have a version number.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"resources: roles")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Required. ",(0,r.kt)("inlineCode",{parentName:"td"},"string ,string & permissions")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Must have a role id . Must have a role name. Must have a list of permissions required.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},"resources: roles: permissions")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Required. ",(0,r.kt)("inlineCode",{parentName:"td"},"string & string")),(0,r.kt)("td",{parentName:"tr",align:"left"},"Must have a name in format ",(0,r.kt)("inlineCode",{parentName:"td"},"<permission-name>:<permission-mode>")," or just ",(0,r.kt)("inlineCode",{parentName:"td"},"<permission-name>")," in case of site role . ",(0,r.kt)("inlineCode",{parentName:"td"},"Optional:")," If this is a site role, it should have a type attribute with value always equal to ",(0,r.kt)("inlineCode",{parentName:"td"},"site_role"),".")))))}m.isMDXComponent=!0}}]);