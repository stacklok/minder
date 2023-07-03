"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[9564],{3905:(e,t,r)=>{r.d(t,{Zo:()=>m,kt:()=>f});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function l(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var a=n.createContext({}),p=function(e){var t=n.useContext(a),r=t;return e&&(r="function"==typeof e?e(t):l(l({},t),e)),r},m=function(e){var t=p(e.components);return n.createElement(a.Provider,{value:t},e.children)},s="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},u=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,i=e.originalType,a=e.parentName,m=c(e,["components","mdxType","originalType","parentName"]),s=p(r),u=o,f=s["".concat(a,".").concat(u)]||s[u]||d[u]||i;return r?n.createElement(f,l(l({ref:t},m),{},{components:r})):n.createElement(f,l({ref:t},m))}));function f(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=r.length,l=new Array(i);l[0]=u;var c={};for(var a in t)hasOwnProperty.call(t,a)&&(c[a]=t[a]);c.originalType=e,c[s]="string"==typeof e?e:o,l[1]=c;for(var p=2;p<i;p++)l[p]=r[p];return n.createElement.apply(null,l)}return n.createElement.apply(null,r)}u.displayName="MDXCreateElement"},3893:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>a,contentTitle:()=>l,default:()=>d,frontMatter:()=>i,metadata:()=>c,toc:()=>p});var n=r(7462),o=(r(7294),r(3905));const i={},l=void 0,c={unversionedId:"cli/medic_completion",id:"cli/medic_completion",title:"medic_completion",description:"medic completion",source:"@site/docs/cli/medic_completion.md",sourceDirName:"cli",slug:"/cli/medic_completion",permalink:"/cli/medic_completion",draft:!1,tags:[],version:"current",frontMatter:{},sidebar:"mediator",previous:{title:"medic_auth_revoke_provider",permalink:"/cli/medic_auth_revoke_provider"},next:{title:"medic_completion_bash",permalink:"/cli/medic_completion_bash"}},a={},p=[{value:"medic completion",id:"medic-completion",level:2},{value:"Synopsis",id:"synopsis",level:3},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3},{value:"Auto generated by spf13/cobra on 30-Jun-2023",id:"auto-generated-by-spf13cobra-on-30-jun-2023",level:6}],m={toc:p},s="wrapper";function d(e){let{components:t,...r}=e;return(0,o.kt)(s,(0,n.Z)({},m,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"medic-completion"},"medic completion"),(0,o.kt)("p",null,"Generate the autocompletion script for the specified shell"),(0,o.kt)("h3",{id:"synopsis"},"Synopsis"),(0,o.kt)("p",null,"Generate the autocompletion script for medic for the specified shell.\nSee each sub-command's help for details on how to use the generated script."),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"  -h, --help   help for completion\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},'      --config string      config file (default is $PWD/config.yaml)\n      --grpc-host string   Server host (default "localhost")\n      --grpc-port int      Server port (default 8090)\n')),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic"},"medic"),"\t - medic controls mediator via the control plane"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic_completion_bash"},"medic completion bash"),"\t - Generate the autocompletion script for bash"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic_completion_fish"},"medic completion fish"),"\t - Generate the autocompletion script for fish"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic_completion_powershell"},"medic completion powershell"),"\t - Generate the autocompletion script for powershell"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/cli/medic_completion_zsh"},"medic completion zsh"),"\t - Generate the autocompletion script for zsh")),(0,o.kt)("h6",{id:"auto-generated-by-spf13cobra-on-30-jun-2023"},"Auto generated by spf13/cobra on 30-Jun-2023"))}d.isMDXComponent=!0}}]);