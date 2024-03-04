"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[3708],{3905:(e,t,n)=>{n.d(t,{Zo:()=>c,kt:()=>m});var r=n(67294);function o(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){o(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function a(e,t){if(null==e)return{};var n,r,o=function(e,t){if(null==e)return{};var n,r,o={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(o[n]=e[n]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var f=r.createContext({}),s=function(e){var t=r.useContext(f),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},c=function(e){var t=s(e.components);return r.createElement(f.Provider,{value:t},e.children)},u="mdxType",p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,o=e.mdxType,i=e.originalType,f=e.parentName,c=a(e,["components","mdxType","originalType","parentName"]),u=s(n),d=o,m=u["".concat(f,".").concat(d)]||u[d]||p[d]||i;return n?r.createElement(m,l(l({ref:t},c),{},{components:n})):r.createElement(m,l({ref:t},c))}));function m(e,t){var n=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=n.length,l=new Array(i);l[0]=d;var a={};for(var f in t)hasOwnProperty.call(t,f)&&(a[f]=t[f]);a.originalType=e,a[u]="string"==typeof e?e:o,l[1]=a;for(var s=2;s<i;s++)l[s]=n[s];return r.createElement.apply(null,l)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},20988:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>f,contentTitle:()=>l,default:()=>p,frontMatter:()=>i,metadata:()=>a,toc:()=>s});var r=n(87462),o=(n(67294),n(3905));const i={title:"minder auth offline-token revoke"},l=void 0,a={unversionedId:"ref/cli/minder_auth_offline-token_revoke",id:"ref/cli/minder_auth_offline-token_revoke",title:"minder auth offline-token revoke",description:"minder auth offline-token revoke",source:"@site/docs/ref/cli/minder_auth_offline-token_revoke.md",sourceDirName:"ref/cli",slug:"/ref/cli/minder_auth_offline-token_revoke",permalink:"/ref/cli/minder_auth_offline-token_revoke",draft:!1,tags:[],version:"current",frontMatter:{title:"minder auth offline-token revoke"},sidebar:"minder",previous:{title:"minder auth offline-token get",permalink:"/ref/cli/minder_auth_offline-token_get"},next:{title:"minder auth offline-token use",permalink:"/ref/cli/minder_auth_offline-token_use"}},f={},s=[{value:"minder auth offline-token revoke",id:"minder-auth-offline-token-revoke",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:s},u="wrapper";function p(e){let{components:t,...n}=e;return(0,o.kt)(u,(0,r.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"minder-auth-offline-token-revoke"},"minder auth offline-token revoke"),(0,o.kt)("p",null,"Revoke an offline token"),(0,o.kt)("h3",{id:"synopsis"},"Synopsis"),(0,o.kt)("p",null,"The minder auth offline-token use command project lets you revoke an offline token\nfor the minder control plane."),(0,o.kt)("p",null,"Offline tokens are used to authenticate to the minder control plane without\nrequiring the user's presence. This is useful for long-running processes\nthat need to authenticate to the control plane."),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"minder auth offline-token revoke [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'  -f, --file string    The file that contains the offline token (default "offline.token")\n  -h, --help           help for revoke\n  -t, --token string   The environment variable to use for the offline token. Also settable through the MINDER_OFFLINE_TOKEN environment variable.\n')),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "api.stacklok.com")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "minder-cli")\n      --identity-url string      Identity server issuer URL (default "https://auth.stacklok.com")\n')),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/ref/cli/minder_auth_offline-token"},"minder auth offline-token"),"\t - Manage offline tokens")))}p.isMDXComponent=!0}}]);