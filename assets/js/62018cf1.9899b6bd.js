"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[7938],{3905:(e,t,r)=>{r.d(t,{Zo:()=>f,kt:()=>u});var i=r(7294);function n(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);t&&(i=i.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,i)}return r}function c(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){n(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function o(e,t){if(null==e)return{};var r,i,n=function(e,t){if(null==e)return{};var r,i,n={},a=Object.keys(e);for(i=0;i<a.length;i++)r=a[i],t.indexOf(r)>=0||(n[r]=e[r]);return n}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(i=0;i<a.length;i++)r=a[i],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(n[r]=e[r])}return n}var l=i.createContext({}),s=function(e){var t=i.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):c(c({},t),e)),r},f=function(e){var t=s(e.components);return i.createElement(l.Provider,{value:t},e.children)},p="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return i.createElement(i.Fragment,{},t)}},m=i.forwardRef((function(e,t){var r=e.components,n=e.mdxType,a=e.originalType,l=e.parentName,f=o(e,["components","mdxType","originalType","parentName"]),p=s(r),m=n,u=p["".concat(l,".").concat(m)]||p[m]||d[m]||a;return r?i.createElement(u,c(c({ref:t},f),{},{components:r})):i.createElement(u,c({ref:t},f))}));function u(e,t){var r=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var a=r.length,c=new Array(a);c[0]=m;var o={};for(var l in t)hasOwnProperty.call(t,l)&&(o[l]=t[l]);o.originalType=e,o[p]="string"==typeof e?e:n,c[1]=o;for(var s=2;s<a;s++)c[s]=r[s];return i.createElement.apply(null,c)}return i.createElement.apply(null,r)}m.displayName="MDXCreateElement"},3095:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>c,default:()=>d,frontMatter:()=>a,metadata:()=>o,toc:()=>s});var i=r(7462),n=(r(7294),r(3905));const a={title:"medic artifact get"},c=void 0,o={unversionedId:"ref/cli/medic_artifact_get",id:"ref/cli/medic_artifact_get",title:"medic artifact get",description:"medic artifact get",source:"@site/docs/ref/cli/medic_artifact_get.md",sourceDirName:"ref/cli",slug:"/ref/cli/medic_artifact_get",permalink:"/ref/cli/medic_artifact_get",draft:!1,tags:[],version:"current",frontMatter:{title:"medic artifact get"},sidebar:"mediator",previous:{title:"medic artifact",permalink:"/ref/cli/medic_artifact"},next:{title:"medic artifact list",permalink:"/ref/cli/medic_artifact_list"}},l={},s=[{value:"medic artifact get",id:"medic-artifact-get",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],f={toc:s},p="wrapper";function d(e){let{components:t,...r}=e;return(0,n.kt)(p,(0,i.Z)({},f,r,{components:t,mdxType:"MDXLayout"}),(0,n.kt)("h2",{id:"medic-artifact-get"},"medic artifact get"),(0,n.kt)("p",null,"Get artifact details"),(0,n.kt)("h3",{id:"synopsis"},"Synopsis"),(0,n.kt)("p",null,"Artifact get will get artifact details from an artifact, for a given ID"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},"medic artifact get [flags]\n")),(0,n.kt)("h3",{id:"options"},"Options"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},"  -h, --help                    help for get\n  -i, --id string               ID of the artifact to get info from\n  -v, --latest-versions int32   Latest artifact versions to retrieve (default 1)\n      --tag string              Specific artifact tag to retrieve\n")),(0,n.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},'      --config string            Config file (default is $PWD/config.yaml)\n      --grpc-host string         Server host (default "staging.stacklok.dev")\n      --grpc-insecure            Allow establishing insecure connections\n      --grpc-port int            Server port (default 443)\n      --identity-client string   Identity server client ID (default "mediator-cli")\n      --identity-realm string    Identity server realm (default "stacklok")\n      --identity-url string      Identity server issuer URL (default "https://auth.staging.stacklok.dev")\n')),(0,n.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("a",{parentName:"li",href:"/ref/cli/medic_artifact"},"medic artifact"),"\t - Manage artifacts within a mediator control plane")))}d.isMDXComponent=!0}}]);