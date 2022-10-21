"use strict";(self.webpackChunkguardian=self.webpackChunkguardian||[]).push([[254],{3905:function(e,n,r){r.d(n,{Zo:function(){return u},kt:function(){return f}});var t=r(7294);function o(e,n,r){return n in e?Object.defineProperty(e,n,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[n]=r,e}function a(e,n){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);n&&(t=t.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),r.push.apply(r,t)}return r}function i(e){for(var n=1;n<arguments.length;n++){var r=null!=arguments[n]?arguments[n]:{};n%2?a(Object(r),!0).forEach((function(n){o(e,n,r[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(r,n))}))}return e}function p(e,n){if(null==e)return{};var r,t,o=function(e,n){if(null==e)return{};var r,t,o={},a=Object.keys(e);for(t=0;t<a.length;t++)r=a[t],n.indexOf(r)>=0||(o[r]=e[r]);return o}(e,n);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(t=0;t<a.length;t++)r=a[t],n.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var l=t.createContext({}),s=function(e){var n=t.useContext(l),r=n;return e&&(r="function"==typeof e?e(n):i(i({},n),e)),r},u=function(e){var n=s(e.components);return t.createElement(l.Provider,{value:n},e.children)},c={inlineCode:"code",wrapper:function(e){var n=e.children;return t.createElement(t.Fragment,{},n)}},d=t.forwardRef((function(e,n){var r=e.components,o=e.mdxType,a=e.originalType,l=e.parentName,u=p(e,["components","mdxType","originalType","parentName"]),d=s(r),f=o,m=d["".concat(l,".").concat(f)]||d[f]||c[f]||a;return r?t.createElement(m,i(i({ref:n},u),{},{components:r})):t.createElement(m,i({ref:n},u))}));function f(e,n){var r=arguments,o=n&&n.mdxType;if("string"==typeof e||o){var a=r.length,i=new Array(a);i[0]=d;var p={};for(var l in n)hasOwnProperty.call(n,l)&&(p[l]=n[l]);p.originalType=e,p.mdxType="string"==typeof e?e:o,i[1]=p;for(var s=2;s<a;s++)i[s]=r[s];return t.createElement.apply(null,i)}return t.createElement.apply(null,r)}d.displayName="MDXCreateElement"},3148:function(e,n,r){r.r(n),r.d(n,{assets:function(){return l},contentTitle:function(){return i},default:function(){return c},frontMatter:function(){return a},metadata:function(){return p},toc:function(){return s}});var t=r(3117),o=(r(7294),r(3905));const a={},i="No Op",p={unversionedId:"providers/noop",id:"providers/noop",title:"No Op",description:"Using a No-op provider, Guardian users can take advantage of policy workflow without adding resources to this provider in Guardian. Users can call the Guardian APIs for approval workflows and appeal management. This can also allow users to locally test Guardian easily without configuring an actual provider.",source:"@site/docs/providers/noop.md",sourceDirName:"providers",slug:"/providers/noop",permalink:"/guardian/docs/providers/noop",draft:!1,editUrl:"https://github.com/odpf/guardian/edit/master/docs/docs/providers/noop.md",tags:[],version:"current",frontMatter:{},sidebar:"docsSidebar",previous:{title:"Metabase",permalink:"/guardian/docs/providers/metabase"},next:{title:"Tableau",permalink:"/guardian/docs/providers/tableau"}},l={},s=[{value:"Provider Configurations",id:"provider-configurations",level:2},{value:"YAML Representation",id:"yaml-representation",level:4}],u={toc:s};function c(e){let{components:n,...r}=e;return(0,o.kt)("wrapper",(0,t.Z)({},u,r,{components:n,mdxType:"MDXLayout"}),(0,o.kt)("h1",{id:"no-op"},"No Op"),(0,o.kt)("p",null,"Using a No-op provider, Guardian users can take advantage of policy workflow without adding resources to this provider in Guardian. Users can call the Guardian APIs for approval workflows and appeal management. This can also allow users to locally test Guardian easily without configuring an actual provider."),(0,o.kt)("h2",{id:"provider-configurations"},"Provider Configurations"),(0,o.kt)("h4",{id:"yaml-representation"},"YAML Representation"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre",className:"language-yaml"},"type: noop\nurn: tes-noop-URN\ncredentials: nil\nresources:\n  - type: noop\n    policy:\n      id: my_policy\n      version: 1\n    roles:\n      - id: test_role\n        name: testRole\n")),(0,o.kt)("p",null,(0,o.kt)("strong",{parentName:"p"},(0,o.kt)("inlineCode",{parentName:"strong"},"Allowed Account Types"))," ",(0,o.kt)("inlineCode",{parentName:"p"},"user"),(0,o.kt)("br",null),"\n",(0,o.kt)("strong",{parentName:"p"},(0,o.kt)("inlineCode",{parentName:"strong"},"Credentials"))," ",(0,o.kt)("inlineCode",{parentName:"p"},"Must be nil"),(0,o.kt)("br",null),"\n",(0,o.kt)("strong",{parentName:"p"},(0,o.kt)("inlineCode",{parentName:"strong"},"Resources Type"))," ",(0,o.kt)("inlineCode",{parentName:"p"},"noop"),(0,o.kt)("br",null),"\n",(0,o.kt)("strong",{parentName:"p"},(0,o.kt)("inlineCode",{parentName:"strong"},"ResourcePermissions")),": ",(0,o.kt)("inlineCode",{parentName:"p"},"Should be empty")))}c.isMDXComponent=!0}}]);