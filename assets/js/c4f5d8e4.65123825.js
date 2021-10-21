/*! For license information please see c4f5d8e4.65123825.js.LICENSE.txt */
(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[195],{2579:function(e,t,a){"use strict";var r=a(4184),n=a.n(r),o=a(7294),s=function(e){var t,a=n()(e.className,{darkBackground:"dark"===e.background,highlightBackground:"highlight"===e.background,lightBackground:"light"===e.background,paddingAll:e.padding.indexOf("all")>=0,paddingBottom:e.padding.indexOf("bottom")>=0,paddingLeft:e.padding.indexOf("left")>=0,paddingRight:e.padding.indexOf("right")>=0,paddingTop:e.padding.indexOf("top")>=0});return t=e.wrapper?o.createElement("div",{className:"container"},e.children):e.children,o.createElement("div",{className:a,id:e.id},t)};s.defaultProps={background:null,padding:[],wrapper:!0},t.Z=s},9260:function(e,t,a){"use strict";var r=a(1721),n=a(4184),o=a.n(n),s=a(7294),l=function(e){function t(){return e.apply(this,arguments)||this}(0,r.Z)(t,e);var a=t.prototype;return a.renderBlock=function(e){var t=Object.assign({},{imageAlign:"left"},e),a=o()("blockElement",this.props.className,{alignCenter:"center"===this.props.align,alignRight:"right"===this.props.align,fourByGridBlock:"fourColumn"===this.props.layout,threeByGridBlock:"threeColumn"===this.props.layout,twoByGridBlock:"twoColumn"===this.props.layout});return s.createElement("div",{className:a,key:t.title},s.createElement("div",{className:"blockContent"},this.renderBlockTitle(t.title),t.content))},a.renderBlockTitle=function(e){return e?s.createElement("h2",null,e):null},a.render=function(){return s.createElement("div",{className:"gridBlock"},this.props.contents.map(this.renderBlock,this))},t}(s.Component);l.defaultProps={align:"left",contents:[],layout:"twoColumn"},t.Z=l},2841:function(e,t,a){"use strict";a.r(t),a.d(t,{default:function(){return u}});var r=a(7294),n=a(6698),o=a(6010),s=a(2263),l=a(2579),i=a(9260),c=a(4996),d=function(){var e=(0,s.Z)().siteConfig;return r.createElement("div",{className:"homeHero"},r.createElement("div",{className:"logo"},r.createElement("img",{src:(0,c.Z)("img/pattern.svg")})),r.createElement("div",{className:"container banner"},r.createElement("div",{className:"row"},r.createElement("div",{className:(0,o.Z)("col col--5")},r.createElement("div",{className:"homeTitle"},e.tagline),r.createElement("small",{className:"homeSubTitle"},"Guardian is a tool for extensible and universal data access with automated access workflows and security controls across data stores, analytical systems, and cloud products."),r.createElement("a",{className:"button",href:"docs/introduction"},"Documentation")),r.createElement("div",{className:(0,o.Z)("col col--1")}),r.createElement("div",{className:(0,o.Z)("col col--6")},r.createElement("div",{className:"text--right"},r.createElement("img",{src:(0,c.Z)("img/banner.svg")}))))))};function u(){var e=(0,s.Z)().siteConfig;return r.createElement(n.Z,{title:e.tagline,description:"Guardian is a tool for extensible and universal data access with automated access workflows and security controls across data stores, analytical systems, and cloud products."},r.createElement(d,null),r.createElement("main",null,r.createElement(l.Z,{className:"textSection wrapper",background:"light"},r.createElement("h1",null,"Built for security"),r.createElement("p",null,"Guardian is the data access and control solution, enabling data teams to accelerate data delivery, reduce risk, and safely unlock more data."),r.createElement(i.Z,{layout:"threeColumn",contents:[{title:"Hybrid access control",content:r.createElement("div",null,"Guardian uses a hybrid approach of role-based and data-centric access control centered around the type of resource being accessed. It also provides time-limited access to ensuring security and compliance.")},{title:"Compliant workflows",content:r.createElement("div",null,"Guardian decouples access controls from data stores to allow for better integration without disrupting your existing data workflow. It also provides custom workflows to make compliance easy for any framework, from GDPR to HITRUST.")},{title:"Auditing",content:r.createElement("div",null,"Automatically produce and maintain complete, interpretable records of data access activities to track every operation. It allows auditors to track requests and access to data, policy changes, how information is being used, and more.")},{title:"Management",content:r.createElement("div",null,"Guardian comes with CLI and APIs which allows you to interact with access workflows effectively. You can manage resources, providers, appeals, and policies and more.")},{title:"Proven",content:r.createElement("div",null,"Guardian is battle tested at large scale across multiple companies. Largest deployment manages access for thousands of resources across different providers.")},{title:"Analytics",content:r.createElement("div",null,"Guardian provides continuous and real-time visibility by analyzing access usage by users, groups, and more. It generates reports about instances of data access and related operations.")}]})),r.createElement(l.Z,{className:"textSection wrapper",background:"dark"},r.createElement("h1",null,"Key Features"),r.createElement("p",null,"Guardian is a data access management tool. It manages resources from various data providers along with the users\u2019 access. Users required to raise an appeal in order to gain access to a particular resource. The appeal will go through several approvals before it is getting approved and granted the access to the user."),r.createElement(i.Z,{layout:"threeColumn",contents:[{title:"Appeal-based access",content:r.createElement("div",null,"Users are expected to create an appeal for accessing data from registered providers. The appeal will get reviewed by the configured approvers before it gives the access to the user.")},{title:"Configurable approval flow",content:r.createElement("div",null,"Approval flow configures what are needed for an appeal to get approved and who are eligible to approve/reject. It can be configured and linked to a provider so that every appeal created to their resources will follow the procedure in order to get approved.")},{title:"External Identity Manager",content:r.createElement("div",null,"Guardian gives the flexibility to use any third-party identity manager for user properties.")}]})),r.createElement(l.Z,{className:"textSection wrapper",background:"light"},r.createElement("h1",null,"Ecosystem"),r.createElement("p",null,"Guardian's extensible system allows new providers to be easily added. Mmultiple providers are supported, including: Metabase, BigQuery, Tableau and more."),r.createElement("div",{className:"row"},r.createElement("div",{className:"col col--4"},r.createElement(i.Z,{contents:[{title:"Providers",content:r.createElement("div",null,"Support various providers like Big Query, Metabase, Tableau, and multiple instances for each provider type.")},{title:"Resources",content:r.createElement("div",null,"Resources from a provider are managed in Guardian's database. There is also an API to update resource's metadata to add additional information.")},{title:"Appeals",content:r.createElement("div",null,"Appeal is created by a user with specifying which resource they want to access along with some other appeal options.")}]})),r.createElement("div",{className:"col col--8"},r.createElement("img",{src:(0,c.Z)("assets/overview.svg")}))))))}},4184:function(e,t){var a;!function(){"use strict";var r={}.hasOwnProperty;function n(){for(var e=[],t=0;t<arguments.length;t++){var a=arguments[t];if(a){var o=typeof a;if("string"===o||"number"===o)e.push(a);else if(Array.isArray(a)){if(a.length){var s=n.apply(null,a);s&&e.push(s)}}else if("object"===o)if(a.toString===Object.prototype.toString)for(var l in a)r.call(a,l)&&a[l]&&e.push(l);else e.push(a.toString())}}return e.join(" ")}e.exports?(n.default=n,e.exports=n):void 0===(a=function(){return n}.apply(t,[]))||(e.exports=a)}()}}]);