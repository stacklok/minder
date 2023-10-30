"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[8297],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>b});var n=r(7294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function a(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var l=n.createContext({}),s=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):a(a({},t),e)),r},p=function(e){var t=s(e.components);return n.createElement(l.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,o=e.originalType,l=e.parentName,p=c(e,["components","mdxType","originalType","parentName"]),u=s(r),m=i,b=u["".concat(l,".").concat(m)]||u[m]||d[m]||o;return r?n.createElement(b,a(a({ref:t},p),{},{components:r})):n.createElement(b,a({ref:t},p))}));function b(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=r.length,a=new Array(o);a[0]=m;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c[u]="string"==typeof e?e:i,a[1]=c;for(var s=2;s<o;s++)a[s]=r[s];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},8406:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>a,default:()=>d,frontMatter:()=>o,metadata:()=>c,toc:()=>s});var n=r(7462),i=(r(7294),r(3905));const o={title:"Architecture",sidebar_position:60},a="System Architecture",c={unversionedId:"developer_guide/architecture",id:"developer_guide/architecture",title:"Architecture",description:"While it is built as a single container, Mediator implements several external",source:"@site/docs/developer_guide/architecture.md",sourceDirName:"developer_guide",slug:"/developer_guide/architecture",permalink:"/developer_guide/architecture",draft:!1,tags:[],version:"current",sidebarPosition:60,frontMatter:{title:"Architecture",sidebar_position:60},sidebar:"mediator",previous:{title:"Get Hacking",permalink:"/developer_guide/get-hacking"},next:{title:"medic",permalink:"/ref/cli/medic"}},l={},s=[],p={toc:s},u="wrapper";function d(e){let{components:t,...r}=e;return(0,i.kt)(u,(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"system-architecture"},"System Architecture"),(0,i.kt)("p",null,"While it is built as a single container, Mediator implements several external\ninterfaces for different components. In addition to the GRPC and HTTP service\nports, it also leverages the ",(0,i.kt)("a",{parentName:"p",href:"https://watermill.io"},"watermill library")," to queue\nand route events within the application."),(0,i.kt)("p",null,"The following is a high-level diagram of the mediator architecture"),(0,i.kt)("mermaid",{value:'flowchart LR\n    subgraph mediator\n        %% flow from top to bottom\n        direction TB\n\n        grpc>GRPC endpoint]\n        click grpc "/api" "GRPC auto-generated documentation"\n        web>HTTP endpoint]\n        click web "https://github.com/stacklok/mediator/blob/main/internal/controlplane/server.go#L210" "Webserver URL registration code"\n        events("watermill")\n        click events "https://watermill.io/docs" "Watermill event processing library"\n\n        handler>Event handlers]\n        click handler "https://github.com/stacklok/mediator/blob/main/cmd/server/app/serve.go#L69" "Registered event handlers"\n    end\n\n    cloud([GitHub])\n    cli("<code>medic</code> CLI")\n    click cli "https://github.com/stacklok/mediator/tree/main/cmd/cli"\n\n    db[(Postgres)]\n    click postgres "/db/mediator_db_schema" "Database schema"\n\n    cli --\x3e grpc\n    cli --OAuth--\x3e web\n    cloud --\x3e web\n\n    grpc --\x3e db\n    web --\x3e db\n\n    web --\x3e events\n\n    events --\x3e handler'}))}d.isMDXComponent=!0}}]);