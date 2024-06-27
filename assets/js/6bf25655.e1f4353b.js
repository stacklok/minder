"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[5584],{78600:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>l,contentTitle:()=>a,default:()=>p,frontMatter:()=>o,metadata:()=>s,toc:()=>d});var t=i(74848),r=i(28453);const o={title:"Automatic Remediations",sidebar_position:60},a="Automatic Remediations in Minder",s={id:"understand/remediations",title:"Automatic Remediations",description:"Minder can perform automatic remediation for many rules in an attempt to resolve problems in your software supply chain, and bring your resources into compliance with your profile.",source:"@site/docs/understand/remediations.md",sourceDirName:"understand",slug:"/understand/remediations",permalink:"/understand/remediations",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:60,frontMatter:{title:"Automatic Remediations",sidebar_position:60},sidebar:"minder",previous:{title:"Alerting",permalink:"/understand/alerts"},next:{title:"Install Minder CLI",permalink:"/getting_started/install_cli"}},l={},d=[{value:"Enabling remediations in a profile",id:"enabling-remediations-in-a-profile",level:3}];function c(e){const n={a:"a",code:"code",em:"em",h1:"h1",h3:"h3",p:"p",pre:"pre",...(0,r.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.h1,{id:"automatic-remediations-in-minder",children:"Automatic Remediations in Minder"}),"\n",(0,t.jsxs)(n.p,{children:["Minder can perform ",(0,t.jsx)(n.em,{children:"automatic remediation"})," for many rules in an attempt to resolve problems in your software supply chain, and bring your resources into compliance with your ",(0,t.jsx)(n.a,{href:"profiles",children:"profile"}),"."]}),"\n",(0,t.jsx)(n.p,{children:"The steps to take during automatic remediation are defined within the rule itself and can perform actions like sending a REST call to an endpoint to change configuration, or creating a pull request with a proposed fix."}),"\n",(0,t.jsx)(n.p,{children:"For example, if you have a rule in your profile that specifies that Secret Scanning should be enabled, and you have enabled automatic remediation in your profile, then Minder will attempt to turn Secret Scanning on in any repositories where it is not enabled."}),"\n",(0,t.jsx)(n.h3,{id:"enabling-remediations-in-a-profile",children:"Enabling remediations in a profile"}),"\n",(0,t.jsx)(n.p,{children:'To activate the remediation feature within a profile, you need to adjust the YAML definition.\nSpecifically, you should set the remediate parameter to "on":'}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'remediate: "on"\n'})}),"\n",(0,t.jsx)(n.p,{children:"Enabling remediation at the profile level means that for any rules included in the profile, a remediation action will be\ntaken for any rule failures."}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'---\nversion: v1\ntype: rule-type\nname: sample_rule\ndef:\n  remediate:\n    type: rest\n    rest:\n      method: PATCH\n      endpoint: "/repos/{{.Entity.Owner}}/{{.Entity.Name}}"\n      body: |\n        { "security_and_analysis": {"secret_scanning": { "status": "enabled" } } }\n'})}),"\n",(0,t.jsxs)(n.p,{children:["In this example, the ",(0,t.jsx)(n.code,{children:"sample_rule"})," defines a remediation action that performs a PATCH request to an endpoint. This\nrequest will modify the state of the repository ensuring it complies with the rule."]}),"\n",(0,t.jsx)(n.p,{children:"Now, let's see how this works in practice within a profile. Consider the following profile configuration with\nremediation turned on:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'version: v1\ntype: profile\nname: sample-profile\ncontext:\n  provider: github\nremediate: "on"\nrepository:\n  - type: sample_rule\n    def:\n      enabled: true\n'})}),"\n",(0,t.jsxs)(n.p,{children:["In this profile, all repositories that do not meet the conditions specified in the ",(0,t.jsx)(n.code,{children:"sample_rule"})," will automatically\nreceive a PATCH request to the specified endpoint. This action will make the repository compliant."]})]})}function p(e={}){const{wrapper:n}={...(0,r.R)(),...e.components};return n?(0,t.jsx)(n,{...e,children:(0,t.jsx)(c,{...e})}):c(e)}},28453:(e,n,i)=>{i.d(n,{R:()=>a,x:()=>s});var t=i(96540);const r={},o=t.createContext(r);function a(e){const n=t.useContext(o);return t.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function s(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:a(e.components),t.createElement(o.Provider,{value:n},e.children)}}}]);