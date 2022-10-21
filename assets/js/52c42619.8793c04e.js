"use strict";(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[944],{3905:function(e,a,t){t.d(a,{Zo:function(){return p},kt:function(){return m}});var n=t(7294);function r(e,a,t){return a in e?Object.defineProperty(e,a,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[a]=t,e}function o(e,a){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);a&&(n=n.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),t.push.apply(t,n)}return t}function i(e){for(var a=1;a<arguments.length;a++){var t=null!=arguments[a]?arguments[a]:{};a%2?o(Object(t),!0).forEach((function(a){r(e,a,t[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(t,a))}))}return e}function s(e,a){if(null==e)return{};var t,n,r=function(e,a){if(null==e)return{};var t,n,r={},o=Object.keys(e);for(n=0;n<o.length;n++)t=o[n],a.indexOf(t)>=0||(r[t]=e[t]);return r}(e,a);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)t=o[n],a.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var l=n.createContext({}),d=function(e){var a=n.useContext(l),t=a;return e&&(t="function"==typeof e?e(a):i(i({},a),e)),t},p=function(e){var a=d(e.components);return n.createElement(l.Provider,{value:a},e.children)},u={inlineCode:"code",wrapper:function(e){var a=e.children;return n.createElement(n.Fragment,{},a)}},c=n.forwardRef((function(e,a){var t=e.components,r=e.mdxType,o=e.originalType,l=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),c=d(t),m=r,f=c["".concat(l,".").concat(m)]||c[m]||u[m]||o;return t?n.createElement(f,i(i({ref:a},p),{},{components:t})):n.createElement(f,i({ref:a},p))}));function m(e,a){var t=arguments,r=a&&a.mdxType;if("string"==typeof e||r){var o=t.length,i=new Array(o);i[0]=c;var s={};for(var l in a)hasOwnProperty.call(a,l)&&(s[l]=a[l]);s.originalType=e,s.mdxType="string"==typeof e?e:r,i[1]=s;for(var d=2;d<o;d++)i[d]=t[d];return n.createElement.apply(null,i)}return n.createElement.apply(null,t)}c.displayName="MDXCreateElement"},5574:function(e,a,t){t.r(a),t.d(a,{assets:function(){return l},contentTitle:function(){return i},default:function(){return u},frontMatter:function(){return o},metadata:function(){return s},toc:function(){return d}});var n=t(3117),r=(t(7294),t(3905));const o={},i="Grafana",s={unversionedId:"providers/grafana",id:"providers/grafana",title:"Grafana",description:"Grafana is open source visualization and analytics software. It allows you to query, visualize, alert on, and explore your metrics no matter where they are stored. In plain English, it provides you with tools to turn your time-series database \\(TSDB\\) data into beautiful graphs and visualizations.",source:"@site/docs/providers/grafana.md",sourceDirName:"providers",slug:"/providers/grafana",permalink:"/guardian/docs/providers/grafana",draft:!1,editUrl:"https://github.com/odpf/guardian/edit/master/docs/docs/providers/grafana.md",tags:[],version:"current",frontMatter:{},sidebar:"docsSidebar",previous:{title:"GCS",permalink:"/guardian/docs/providers/gcs"},next:{title:"Metabase",permalink:"/guardian/docs/providers/metabase"}},l={},d=[{value:"Grafana Resources",id:"grafana-resources",level:3},{value:"Grafana Users",id:"grafana-users",level:3},{value:"Access Flow",id:"access-flow",level:3},{value:"Authentication",id:"authentication",level:3},{value:"Configuration",id:"configuration",level:2},{value:"<code>credentials</code>",id:"credentials",level:3},{value:"<code>GrafanaResourceType</code>",id:"grafanaresourcetype",level:3},{value:"<code>GrafanaResourcePermission</code>",id:"grafanaresourcepermission",level:3},{value:"Grafana Access Creation",id:"grafana-access-creation",level:2}],p={toc:d};function u(e){let{components:a,...t}=e;return(0,r.kt)("wrapper",(0,n.Z)({},p,t,{components:a,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"grafana"},"Grafana"),(0,r.kt)("p",null,"Grafana is open source visualization and analytics software. It allows you to query, visualize, alert on, and explore your metrics no matter where they are stored. In plain English, it provides you with tools to turn your time-series database ","(","TSDB",")"," data into beautiful graphs and visualizations."),(0,r.kt)("h3",{id:"grafana-resources"},"Grafana Resources"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},(0,r.kt)("strong",{parentName:"p"},"Dashboards: ")," is a set of one or more panels organized and arranged into one or more rows. Grafana ships with a variety of Panels. Each panel can interact with data from any configured Grafana Data Source. A Grafana dashboard provides a way of displaying metrics and log data in the form of visualizations and reporting dashboards.")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("p",{parentName:"li"},(0,r.kt)("strong",{parentName:"p"},"Folders: ")," are a way to organize and group dashboards - very useful if you have a lot of dashboards or multiple teams using the same Grafana instance."))),(0,r.kt)("h3",{id:"grafana-users"},"Grafana Users"),(0,r.kt)("p",null,(0,r.kt)("strong",{parentName:"p"},"Users")," are named accounts in Grafana with granted permissions to access resources throughout Grafana."),(0,r.kt)("p",null,(0,r.kt)("strong",{parentName:"p"},"Organizations")," are groups of users on a server. Users can belong to one or more organizations, but each user must belong to at least one organization. Data sources, plugins, and dashboards are associated with organizations. Members of organizations have permissions based on their role in the organization."),(0,r.kt)("p",null,(0,r.kt)("strong",{parentName:"p"},"Teams")," are groups of users within the same organization. Teams allow you to grant permissions for a group of users."),(0,r.kt)("h3",{id:"access-flow"},"Access Flow"),(0,r.kt)("p",null,"Grafana itself manages its user access at both ",(0,r.kt)("em",{parentName:"p"},"folder level")," and ",(0,r.kt)("em",{parentName:"p"},"dashboard level"),", while Guardian lets each individual user have access directly at the ",(0,r.kt)("em",{parentName:"p"},"dashboard level"),"."),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Access is based on the role a user has on a resource."),(0,r.kt)("li",{parentName:"ul"},"Roles can be either of the three: viewer, editor or admin."),(0,r.kt)("li",{parentName:"ul"},"Roles are inherited from the parent folders to a dashboard."),(0,r.kt)("li",{parentName:"ul"},"Although we can assign a different but higher role at the dashboard level.")),(0,r.kt)("h3",{id:"authentication"},"Authentication"),(0,r.kt)("p",null,"Guardian requires ",(0,r.kt)("strong",{parentName:"p"},"host"),", ",(0,r.kt)("strong",{parentName:"p"},"username")," and ",(0,r.kt)("strong",{parentName:"p"},"password")," of an administrator user in Grafana."),(0,r.kt)("p",null,"Example provider config for grafana:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},". . .\ncredentials:\n  host: http://localhost:3000\n  user: admin@localhost\n  password: password\n")),(0,r.kt)("h2",{id:"configuration"},"Configuration"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-yaml"},'type: grafana\nurn: 1\nlabels:\n  entity: xyz\n  landscape: abc\ncredentials:\n  host: http://localhost:4000\n  username: admin@localhost\n  password: password\nappeal:\n  allow_permanent_access: true\n  allow_active_access_extension_in: "7d"\nresources:\n  - type: dashboard\n    policy:\n      id: policy_x\n      version: 1\n    roles:\n      - id: viewer\n        name: Viewer\n        permissions:\n          - view\n      - id: editor\n        name: Editor\n        permissions:\n          - edit\n      - id: admin\n        name: Admin\n        permissions:\n          - admin\n')),(0,r.kt)("h3",{id:"credentials"},(0,r.kt)("inlineCode",{parentName:"h3"},"credentials")),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:"left"},"Fields"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Type"),(0,r.kt)("th",{parentName:"tr",align:null},"Description"),(0,r.kt)("th",{parentName:"tr",align:null},"Required"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"host"))),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")),(0,r.kt)("td",{parentName:"tr",align:null},"Grafana instance host. ",(0,r.kt)("br",null),"Example: ",(0,r.kt)("inlineCode",{parentName:"td"},"http://localhost:3000")),(0,r.kt)("td",{parentName:"tr",align:null},"Yes")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"username"))),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"email")),(0,r.kt)("td",{parentName:"tr",align:null},"Email address of an account that has Administration permission."),(0,r.kt)("td",{parentName:"tr",align:null},"Yes")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"password"))),(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")),(0,r.kt)("td",{parentName:"tr",align:null},"Account's password."),(0,r.kt)("td",{parentName:"tr",align:null},"Yes")))),(0,r.kt)("h3",{id:"grafanaresourcetype"},(0,r.kt)("inlineCode",{parentName:"h3"},"GrafanaResourceType")),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"folders")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("inlineCode",{parentName:"li"},"dashboards")," - Direct dashboard level access via Guardian.")),(0,r.kt)("h3",{id:"grafanaresourcepermission"},(0,r.kt)("inlineCode",{parentName:"h3"},"GrafanaResourcePermission")),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:"left"},"Type"),(0,r.kt)("th",{parentName:"tr",align:null},"Details"),(0,r.kt)("th",{parentName:"tr",align:"left"},"Required"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:"left"},(0,r.kt)("inlineCode",{parentName:"td"},"string")),(0,r.kt)("td",{parentName:"tr",align:null},"role_id enum : ","[",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"viewer")),", ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"editor"))," or ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"admin")),"]",(0,r.kt)("br",null)," role_name enum ","[",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"Viewer")),", ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"Editor"))," or ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"Admin")),"]"," ",(0,r.kt)("br",null)," role_permissions enum ","[",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"view")),", ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"edit"))," or ",(0,r.kt)("strong",{parentName:"td"},(0,r.kt)("inlineCode",{parentName:"strong"},"admin"))," ]"),(0,r.kt)("td",{parentName:"tr",align:"left"},"Yes")))),(0,r.kt)("h2",{id:"grafana-access-creation"},"Grafana Access Creation"),(0,r.kt)("p",null,"Guardian looks for the resource we want to grant access to and append new permissions to the existing ones. In case, the resource does not exist it returns errors."))}u.isMDXComponent=!0}}]);