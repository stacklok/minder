"use strict";(self.webpackChunkstacklok=self.webpackChunkstacklok||[]).push([[4018],{21133:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>a,contentTitle:()=>l,default:()=>h,frontMatter:()=>r,metadata:()=>o,toc:()=>d});var t=i(74848),s=i(28453);const r={title:"Install Minder CLI",sidebar_position:10},l="Installing the Minder CLI",o={id:"getting_started/install_cli",title:"Install Minder CLI",description:"Minder consists of two components: a server-side application, and the minder",source:"@site/docs/getting_started/install_cli.md",sourceDirName:"getting_started",slug:"/getting_started/install_cli",permalink:"/getting_started/install_cli",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Install Minder CLI",sidebar_position:10},sidebar:"minder",previous:{title:"Alerting",permalink:"/understand/alerts"},next:{title:"Quickstart with Minder (< 1 min)",permalink:"/getting_started/quickstart"}},a={},d=[{value:"MacOS (Homebrew)",id:"macos-homebrew",level:2},{value:"Windows (Winget)",id:"windows-winget",level:2},{value:"Linux",id:"linux",level:2},{value:"Building from source",id:"building-from-source",level:2}];function c(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",p:"p",pre:"pre",...(0,s.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.h1,{id:"installing-the-minder-cli",children:"Installing the Minder CLI"}),"\n",(0,t.jsxs)(n.p,{children:["Minder consists of two components: a server-side application, and the ",(0,t.jsx)(n.code,{children:"minder"}),"\nCLI application for interacting with the server.  Minder is built for ",(0,t.jsx)(n.code,{children:"amd64"}),"\nand ",(0,t.jsx)(n.code,{children:"arm64"})," architectures on Windows, MacOS, and Linux."]}),"\n",(0,t.jsxs)(n.p,{children:["You can install ",(0,t.jsx)(n.code,{children:"minder"})," using one of the following methods:"]}),"\n",(0,t.jsx)(n.h2,{id:"macos-homebrew",children:"MacOS (Homebrew)"}),"\n",(0,t.jsxs)(n.p,{children:["The easiest way to install ",(0,t.jsx)(n.code,{children:"minder"})," is through ",(0,t.jsx)(n.a,{href:"https://brew.sh/",children:"Homebrew"}),":"]}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"brew install stacklok/tap/minder\n"})}),"\n",(0,t.jsxs)(n.p,{children:["Alternatively, you can ",(0,t.jsxs)(n.a,{href:"https://github.com/stacklok/minder/releases",children:["download a ",(0,t.jsx)(n.code,{children:".tar.gz"})," release"]})," and unpack it with the following:"]}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"tar -xzf minder_${RELEASE}_darwin_${ARCH}.tar.gz minder\nxattr -d com.apple.quarantine minder\n"})}),"\n",(0,t.jsx)(n.h2,{id:"windows-winget",children:"Windows (Winget)"}),"\n",(0,t.jsxs)(n.p,{children:["For Windows, the built-in ",(0,t.jsx)(n.code,{children:"winget"})," tool is the simplest way to install ",(0,t.jsx)(n.code,{children:"minder"}),":"]}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"winget install stacklok.minder\n"})}),"\n",(0,t.jsxs)(n.p,{children:["Alternatively, you can ",(0,t.jsxs)(n.a,{href:"https://github.com/stacklok/minder/releases",children:["download a zipfile containing the ",(0,t.jsx)(n.code,{children:"minder"})," CLI"]})," and install the binary yourself."]}),"\n",(0,t.jsx)(n.h2,{id:"linux",children:"Linux"}),"\n",(0,t.jsxs)(n.p,{children:["We provide pre-built static binaries for Linux at: ",(0,t.jsx)(n.a,{href:"https://github.com/stacklok/minder/releases",children:"https://github.com/stacklok/minder/releases"}),"."]}),"\n",(0,t.jsx)(n.h2,{id:"building-from-source",children:"Building from source"}),"\n",(0,t.jsxs)(n.p,{children:["You can also build the ",(0,t.jsx)(n.code,{children:"minder"})," CLI from source using ",(0,t.jsx)(n.code,{children:"go install github.com/stacklok/minder/cmd/cli@latest"}),", or by ",(0,t.jsx)(n.a,{href:"https://github.com/stacklok/minder#build-from-source",children:"following the build instructions in the repository"}),"."]})]})}function h(e={}){const{wrapper:n}={...(0,s.R)(),...e.components};return n?(0,t.jsx)(n,{...e,children:(0,t.jsx)(c,{...e})}):c(e)}},28453:(e,n,i)=>{i.d(n,{R:()=>l,x:()=>o});var t=i(96540);const s={},r=t.createContext(s);function l(e){const n=t.useContext(r);return t.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function o(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(s):e.components||s:l(e.components),t.createElement(r.Provider,{value:n},e.children)}}}]);