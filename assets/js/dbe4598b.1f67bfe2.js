"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[8150],{36109:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>o,contentTitle:()=>a,default:()=>c,frontMatter:()=>r,metadata:()=>l,toc:()=>d});var s=n(74848),i=n(28453);const r={title:"Rule evaluations",sidebar_position:50},a="Rule evaluations",l={id:"understand/rule_evaluation",title:"Rule evaluations",description:"When Minder evaluates the rules in your profiles, it records the state of those evaluations. When those rules are not satisfied because the criteria that you defined was not met, it will issue alerts.",source:"@site/docs/understand/rule_evaluation.md",sourceDirName:"understand",slug:"/understand/rule_evaluation",permalink:"/understand/rule_evaluation",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:50,frontMatter:{title:"Rule evaluations",sidebar_position:50},sidebar:"minder",previous:{title:"Repository registration",permalink:"/understand/repository_registration"},next:{title:"Alerting",permalink:"/understand/alerts"}},o={},d=[{value:"Viewing rule evaluations",id:"viewing-rule-evaluations",level:3},{value:"Evaluation status",id:"evaluation-status",level:3},{value:"Alert status",id:"alert-status",level:3},{value:"Remediation status",id:"remediation-status",level:3}];function u(e){const t={a:"a",code:"code",em:"em",h1:"h1",h3:"h3",header:"header",li:"li",p:"p",strong:"strong",ul:"ul",...(0,i.R)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(t.header,{children:(0,s.jsx)(t.h1,{id:"rule-evaluations",children:"Rule evaluations"})}),"\n",(0,s.jsxs)(t.p,{children:["When Minder evaluates the ",(0,s.jsx)(t.a,{href:"/understand/profiles",children:"rules in your profiles"}),", it records the state of those evaluations. When those rules are not satisfied because the criteria that you defined was not met, it will issue ",(0,s.jsx)(t.a,{href:"/understand/alerts",children:"alerts"}),"."]}),"\n",(0,s.jsx)(t.p,{children:"Minder evaluates the rules in your profile:"}),"\n",(0,s.jsxs)(t.ul,{children:["\n",(0,s.jsx)(t.li,{children:"When the repository is registered"}),"\n",(0,s.jsx)(t.li,{children:"When the profile is updated"}),"\n",(0,s.jsx)(t.li,{children:"When activity occurs within the repository"}),"\n"]}),"\n",(0,s.jsx)(t.p,{children:"In a rule evaluation, you'll see:"}),"\n",(0,s.jsxs)(t.ul,{children:["\n",(0,s.jsx)(t.li,{children:"The time that a rule evaluation was performed"}),"\n",(0,s.jsx)(t.li,{children:"The entity that was examined (a repository, artifact, or pull request)"}),"\n",(0,s.jsx)(t.li,{children:"The rule that was evaluated"}),"\n",(0,s.jsx)(t.li,{children:"The status of the evaluation"}),"\n",(0,s.jsxs)(t.li,{children:["Whether an ",(0,s.jsx)(t.a,{href:"/understand/alerts",children:"alert"})," was opened"]}),"\n",(0,s.jsxs)(t.li,{children:["Whether ",(0,s.jsx)(t.a,{href:"/understand/remediations",children:"automatic remediation"})," was performed, and if so, its status"]}),"\n"]}),"\n",(0,s.jsx)(t.h3,{id:"viewing-rule-evaluations",children:"Viewing rule evaluations"}),"\n",(0,s.jsxs)(t.p,{children:["To view the rule evaluations, run ",(0,s.jsx)(t.a,{href:"/ref/cli/minder_history_list",children:(0,s.jsx)(t.code,{children:"minder history list"})}),". You can query the history to only look at certain entities, profiles, or statuses."]}),"\n",(0,s.jsx)(t.h3,{id:"evaluation-status",children:"Evaluation status"}),"\n",(0,s.jsxs)(t.p,{children:["The ",(0,s.jsx)(t.em,{children:"status"})," of a rule evaluation describes the outcome of executing the rule against an entity. Possible statuses are:"]}),"\n",(0,s.jsxs)(t.ul,{children:["\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Success"}),": the entity was evaluated and is in compliance with the rule. For example, given the ",(0,s.jsx)(t.a,{href:"../ref/rules/secret_scanning",children:(0,s.jsx)(t.code,{children:"secret_scanning"})})," rule, this means that secret scanning is enabled on the repository being evaluated."]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Failure"}),": the entity was evaluated and is ",(0,s.jsx)(t.em,{children:"not"})," in compliance with the rule. For example, given the ",(0,s.jsx)(t.a,{href:"../ref/rules/secret_scanning",children:(0,s.jsx)(t.code,{children:"secret_scanning"})})," rule, this means that secret scanning is ",(0,s.jsx)(t.em,{children:"not"})," enabled on the repository being evaluated."]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Error"}),": the rule could not be evaluated for some reason. For example, the server being evaluated was not online or could not be contacted."]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Pending"}),": the rule has not yet been evaluated. Once evaluated, it will move into a state that represents the evaluation."]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Skipped"}),": the rule is not configured for the entity. For example, given the ",(0,s.jsx)(t.a,{href:"../ref/rules/secret_scanning",children:(0,s.jsx)(t.code,{children:"secret_scanning"})})," rule, it can be configured to skip private repositories."]}),"\n"]}),"\n",(0,s.jsx)(t.h3,{id:"alert-status",children:"Alert status"}),"\n",(0,s.jsxs)(t.p,{children:["When a rule evaluation occurs, an ",(0,s.jsx)(t.a,{href:"/understand/alerts",children:"alert"})," may be created. Each rule evaluation has an alert status:"]}),"\n",(0,s.jsxs)(t.ul,{children:["\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Success"}),": an alert was created"]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Failure"}),": there was an issue creating the alert; for example, GitHub failed to create a security advisory"]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Skipped"}),": the rule evaluation was successful, meaning an alert should not be created, or the profile is not configured to generate alerts"]}),"\n"]}),"\n",(0,s.jsx)(t.h3,{id:"remediation-status",children:"Remediation status"}),"\n",(0,s.jsxs)(t.ul,{children:["\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Success"}),": the issue was automatically remediated"]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Failure"}),": the issue could not be automatically remediated"]}),"\n",(0,s.jsxs)(t.li,{children:[(0,s.jsx)(t.strong,{children:"Skipped"}),": the rule evaluation was successful, meaning remediation should not be performed, or the profile is not configured to automatically remediate"]}),"\n"]})]})}function c(e={}){const{wrapper:t}={...(0,i.R)(),...e.components};return t?(0,s.jsx)(t,{...e,children:(0,s.jsx)(u,{...e})}):u(e)}},28453:(e,t,n)=>{n.d(t,{R:()=>a,x:()=>l});var s=n(96540);const i={},r=s.createContext(i);function a(e){const t=s.useContext(r);return s.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function l(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(i):e.components||i:a(e.components),s.createElement(r.Provider,{value:t},e.children)}}}]);