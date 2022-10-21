"use strict";(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[923],{3905:function(e,n,t){t.d(n,{Zo:function(){return p},kt:function(){return m}});var r=t(7294);function a(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function o(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);n&&(r=r.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,r)}return t}function l(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?o(Object(t),!0).forEach((function(n){a(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function i(e,n){if(null==e)return{};var t,r,a=function(e,n){if(null==e)return{};var t,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||(a[t]=e[t]);return a}(e,n);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)t=o[r],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(a[t]=e[t])}return a}var u=r.createContext({}),c=function(e){var n=r.useContext(u),t=n;return e&&(t="function"==typeof e?e(n):l(l({},n),e)),t},p=function(e){var n=c(e.components);return r.createElement(u.Provider,{value:n},e.children)},s={inlineCode:"code",wrapper:function(e){var n=e.children;return r.createElement(r.Fragment,{},n)}},d=r.forwardRef((function(e,n){var t=e.components,a=e.mdxType,o=e.originalType,u=e.parentName,p=i(e,["components","mdxType","originalType","parentName"]),d=c(t),m=a,f=d["".concat(u,".").concat(m)]||d[m]||s[m]||o;return t?r.createElement(f,l(l({ref:n},p),{},{components:t})):r.createElement(f,l({ref:n},p))}));function m(e,n){var t=arguments,a=n&&n.mdxType;if("string"==typeof e||a){var o=t.length,l=new Array(o);l[0]=d;var i={};for(var u in n)hasOwnProperty.call(n,u)&&(i[u]=n[u]);i.originalType=e,i.mdxType="string"==typeof e?e:a,l[1]=i;for(var c=2;c<o;c++)l[c]=t[c];return r.createElement.apply(null,l)}return r.createElement.apply(null,t)}d.displayName="MDXCreateElement"},5162:function(e,n,t){t.d(n,{Z:function(){return l}});var r=t(7294),a=t(6010),o="tabItem_Ymn6";function l(e){let{children:n,hidden:t,className:l}=e;return r.createElement("div",{role:"tabpanel",className:(0,a.Z)(o,l),hidden:t},n)}},5488:function(e,n,t){t.d(n,{Z:function(){return m}});var r=t(3117),a=t(7294),o=t(6010),l=t(2389),i=t(7392),u=t(7094),c=t(2466),p="tabList__CuJ",s="tabItem_LNqP";function d(e){var n,t;const{lazy:l,block:d,defaultValue:m,values:f,groupId:y,className:v}=e,h=a.Children.map(e.children,(e=>{if((0,a.isValidElement)(e)&&"value"in e.props)return e;throw new Error("Docusaurus error: Bad <Tabs> child <"+("string"==typeof e.type?e.type:e.type.name)+'>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.')})),b=null!=f?f:h.map((e=>{let{props:{value:n,label:t,attributes:r}}=e;return{value:n,label:t,attributes:r}})),g=(0,i.l)(b,((e,n)=>e.value===n.value));if(g.length>0)throw new Error('Docusaurus error: Duplicate values "'+g.map((e=>e.value)).join(", ")+'" found in <Tabs>. Every value needs to be unique.');const k=null===m?m:null!=(n=null!=m?m:null==(t=h.find((e=>e.props.default)))?void 0:t.props.value)?n:h[0].props.value;if(null!==k&&!b.some((e=>e.value===k)))throw new Error('Docusaurus error: The <Tabs> has a defaultValue "'+k+'" but none of its children has the corresponding value. Available values are: '+b.map((e=>e.value)).join(", ")+". If you intend to show no default tab, use defaultValue={null} instead.");const{tabGroupChoices:w,setTabGroupChoices:N}=(0,u.U)(),[O,T]=(0,a.useState)(k),P=[],{blockElementScrollPositionUntilNextRender:C}=(0,c.o5)();if(null!=y){const e=w[y];null!=e&&e!==O&&b.some((n=>n.value===e))&&T(e)}const E=e=>{const n=e.currentTarget,t=P.indexOf(n),r=b[t].value;r!==O&&(C(n),T(r),null!=y&&N(y,String(r)))},x=e=>{var n;let t=null;switch(e.key){case"ArrowRight":{var r;const n=P.indexOf(e.currentTarget)+1;t=null!=(r=P[n])?r:P[0];break}case"ArrowLeft":{var a;const n=P.indexOf(e.currentTarget)-1;t=null!=(a=P[n])?a:P[P.length-1];break}}null==(n=t)||n.focus()};return a.createElement("div",{className:(0,o.Z)("tabs-container",p)},a.createElement("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,o.Z)("tabs",{"tabs--block":d},v)},b.map((e=>{let{value:n,label:t,attributes:l}=e;return a.createElement("li",(0,r.Z)({role:"tab",tabIndex:O===n?0:-1,"aria-selected":O===n,key:n,ref:e=>P.push(e),onKeyDown:x,onFocus:E,onClick:E},l,{className:(0,o.Z)("tabs__item",s,null==l?void 0:l.className,{"tabs__item--active":O===n})}),null!=t?t:n)}))),l?(0,a.cloneElement)(h.filter((e=>e.props.value===O))[0],{className:"margin-top--md"}):a.createElement("div",{className:"margin-top--md"},h.map(((e,n)=>(0,a.cloneElement)(e,{key:n,hidden:e.props.value!==O})))))}function m(e){const n=(0,l.Z)();return a.createElement(d,(0,r.Z)({key:String(n)},e))}},5473:function(e,n,t){t.r(n),t.d(n,{assets:function(){return p},contentTitle:function(){return u},default:function(){return m},frontMatter:function(){return i},metadata:function(){return c},toc:function(){return s}});var r=t(3117),a=(t(7294),t(3905)),o=t(5488),l=t(5162);const i={},u="Create a policy",c={unversionedId:"tour/create-policy",id:"tour/create-policy",title:"Create a policy",description:"Pre-Requisites",source:"@site/docs/tour/create-policy.md",sourceDirName:"tour",slug:"/tour/create-policy",permalink:"/guardian/docs/tour/create-policy",draft:!1,editUrl:"https://github.com/odpf/guardian/edit/master/docs/docs/tour/create-policy.md",tags:[],version:"current",frontMatter:{},sidebar:"docsSidebar",previous:{title:"Configure client",permalink:"/guardian/docs/tour/configuration"},next:{title:"Create a provider",permalink:"/guardian/docs/tour/create-provider"}},p={},s=[{value:"Pre-Requisites",id:"pre-requisites",level:3},{value:"Example Policy",id:"example-policy",level:3},{value:"Policies can be created in the following ways:",id:"policies-can-be-created-in-the-following-ways",level:4}],d={toc:s};function m(e){let{components:n,...t}=e;return(0,a.kt)("wrapper",(0,r.Z)({},d,t,{components:n,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"create-a-policy"},"Create a policy"),(0,a.kt)("h3",{id:"pre-requisites"},"Pre-Requisites"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("a",{parentName:"li",href:"/guardian/docs/tour/configuration#starting-the-server"},"Setting up server")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("a",{parentName:"li",href:"/guardian/docs/tour/configuration#client-configuration"},"Setting up the CLI")," (if you want to create policy using CLI)")),(0,a.kt)("h3",{id:"example-policy"},"Example Policy"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-yaml"},"id: my-first-policy\nsteps:\n  - name: resource_owner_approval\n    description: approval from resource owner\n    strategy: manual\n    approvers:\n      - $appeal.resource.details.owner\n  - name: admin_approval\n    description: approval from admin (John Doe)\n    strategy: manual\n    approvers:\n      - john.doe@company.com\nappeal:\n  - duration_options:\n    - name: 1 day\n      value: 24h\n    - name: 1 week\n      value: 98h\n  - allow_on_behalf: false\n")),(0,a.kt)("p",null,"Check ",(0,a.kt)("a",{parentName:"p",href:"/guardian/docs/reference/policy"},"policy reference")," for more details on the policy configuration.",(0,a.kt)("br",null)),(0,a.kt)("p",null,(0,a.kt)("strong",{parentName:"p"},"Explanation of this Policy example"),(0,a.kt)("br",null),"\nWhen a Guardian user creates an appeal to the BigQuery resource (Playground here), this policy will applied, and the approvals required to approve that appeal are in the order as follows: ",(0,a.kt)("br",null)),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},"Approval from the resource owner ( this information is contained in the resource details object), and"),(0,a.kt)("li",{parentName:"ol"},"Approval from John Doe as an admin")),(0,a.kt)("h4",{id:"policies-can-be-created-in-the-following-ways"},"Policies can be created in the following ways:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},"Using ",(0,a.kt)("inlineCode",{parentName:"li"},"guardian policy create")," CLI command"),(0,a.kt)("li",{parentName:"ol"},"Calling to ",(0,a.kt)("inlineCode",{parentName:"li"},"POST /api/v1beta1/policies")," API")),(0,a.kt)(o.Z,{groupId:"api",mdxType:"Tabs"},(0,a.kt)(l.Z,{value:"cli",label:"CLI",default:!0,mdxType:"TabItem"},(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},"$ guardian policy create --file=<path to the policy.yaml file>\n"))),(0,a.kt)(l.Z,{value:"http",label:"HTTP",mdxType:"TabItem"},(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-bash"},'$ curl --request POST \'{{HOST}}/api/v1beta1/policies\' \\\n--header \'Content-Type: application/json\' \\\n--data-raw \'{\n  "id": "my-first-policy",\n  "steps": [\n    {\n      "name": "resource_owner_approval",\n      "description": "Approval from Resource owner",\n      "strategy": "manual",\n      "approvers": [\n        "$appeal.resource.details.owner"\n      ]\n    },\n    {\n      "name": "admin_approval",\n      "description": "Approval from the Admin (John Doe)",\n      "strategy": "manual",\n      "approvers": [\n        "john.doe@company.com"\n      ]\n    }\n  ],\n   "appeal": {\n        "duration_options": [\n            {\n                "name": "1 Day",\n                "value": "24h"\n            },\n            {\n                "name": "3 Day",\n                "value": "72h"\n            }\n        ],\n        "allow_on_behalf": true\n    }\n}\'\n')))),(0,a.kt)("p",null,(0,a.kt)("strong",{parentName:"p"},"Note")," : For using the CLI tool, create a Policy.yaml file using the example configurations shown above and provide the path to it here."))}m.isMDXComponent=!0}}]);