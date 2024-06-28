"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[663],{38502:(e,t,i)=>{i.r(t),i.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>h,frontMatter:()=>a,metadata:()=>l,toc:()=>d});var r=i(74848),n=i(28453);const a={title:"Setting up a profile for automatic remediation",sidebar_position:60},o="Setting up a Profile for automatic remediation",l={id:"how-to/setup-autoremediation",title:"Setting up a profile for automatic remediation",description:"Prerequisites",source:"@site/docs/how-to/setup-autoremediation.md",sourceDirName:"how-to",slug:"/how-to/setup-autoremediation",permalink:"/how-to/setup-autoremediation",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:60,frontMatter:{title:"Setting up a profile for automatic remediation",sidebar_position:60},sidebar:"minder",previous:{title:"Check artifact provenance",permalink:"/how-to/artifact_signatures"},next:{title:"Automatic remediation via Pull Request",permalink:"/how-to/remediate-pullrequest"}},s={},d=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Create a rule type that you want to use auto-remediation on",id:"create-a-rule-type-that-you-want-to-use-auto-remediation-on",level:2},{value:"Create a profile",id:"create-a-profile",level:2},{value:"Limitations",id:"limitations",level:2}];function c(e){const t={a:"a",code:"code",h1:"h1",h2:"h2",li:"li",p:"p",pre:"pre",ul:"ul",...(0,n.R)(),...e.components};return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(t.h1,{id:"setting-up-a-profile-for-automatic-remediation",children:"Setting up a Profile for automatic remediation"}),"\n",(0,r.jsx)(t.h2,{id:"prerequisites",children:"Prerequisites"}),"\n",(0,r.jsxs)(t.ul,{children:["\n",(0,r.jsxs)(t.li,{children:["The ",(0,r.jsx)(t.code,{children:"minder"})," CLI application"]}),"\n",(0,r.jsx)(t.li,{children:"A Minder account"}),"\n",(0,r.jsx)(t.li,{children:"An enrolled Provider (e.g., GitHub) and registered repositories"}),"\n"]}),"\n",(0,r.jsx)(t.h2,{id:"create-a-rule-type-that-you-want-to-use-auto-remediation-on",children:"Create a rule type that you want to use auto-remediation on"}),"\n",(0,r.jsxs)(t.p,{children:["The ",(0,r.jsx)(t.code,{children:"remediate"})," feature is available for all rule types that have the ",(0,r.jsx)(t.code,{children:"remediate"})," section defined in their\n",(0,r.jsx)(t.code,{children:"<alert-type>.yaml"})," file. When the ",(0,r.jsx)(t.code,{children:"remediate"})," feature is turned ",(0,r.jsx)(t.code,{children:"on"}),", Minder will try to automatically remediate failed\nrules based on their type, i.e., by processing a REST call to enable/disable a non-compliant repository setting or by\ncreating a pull request with a proposed fix."]}),"\n",(0,r.jsx)(t.p,{children:"In this example, we will use a rule type that checks if a repository allows having force pushes on their main branch,\nwhich is considered a security risk. If their setting allows for force pushes, Minder will automatically remediate it\nand disable it."}),"\n",(0,r.jsxs)(t.p,{children:["The rule type is called ",(0,r.jsx)(t.code,{children:"branch_protection_allow_force_pushes.yaml"})," and is one of the reference rule types provided by\nthe Minder team."]}),"\n",(0,r.jsxs)(t.p,{children:["Fetch all the reference rules by cloning the ",(0,r.jsx)(t.a,{href:"https://github.com/stacklok/minder-rules-and-profiles",children:"minder-rules-and-profiles repository"}),"."]}),"\n",(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-bash",children:"git clone https://github.com/stacklok/minder-rules-and-profiles.git\n"})}),"\n",(0,r.jsx)(t.p,{children:"In that directory, you can find all the reference rules and profiles."}),"\n",(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-bash",children:"cd minder-rules-and-profiles\n"})}),"\n",(0,r.jsxs)(t.p,{children:["Create the ",(0,r.jsx)(t.code,{children:"branch_protection_allow_force_pushes"})," rule type in Minder:"]}),"\n",(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-bash",children:"minder ruletype create -f rule-types/github/branch_protection_allow_force_pushes.yaml\n"})}),"\n",(0,r.jsx)(t.h2,{id:"create-a-profile",children:"Create a profile"}),"\n",(0,r.jsx)(t.p,{children:"Next, create a profile that applies the rule to all registered repositories."}),"\n",(0,r.jsxs)(t.p,{children:["Create a new file called ",(0,r.jsx)(t.code,{children:"profile.yaml"})," using the following profile definition and enable automatic remediation by setting\n",(0,r.jsx)(t.code,{children:"remediate"})," to ",(0,r.jsx)(t.code,{children:"on"}),". The other available values are ",(0,r.jsx)(t.code,{children:"off"}),"(default) and ",(0,r.jsx)(t.code,{children:"dry_run"}),"."]}),"\n",(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-yaml",children:'---\nversion: v1\ntype: profile\nname: disable-force-push-profile\ncontext:\n  provider: github\nremediate: "on"\nrepository:\n  - type: branch_protection_allow_force_pushes\n    params:\n      branch: main\n    def:\n      allow_force_pushes: false\n'})}),"\n",(0,r.jsx)(t.p,{children:"Create the profile in Minder:"}),"\n",(0,r.jsx)(t.pre,{children:(0,r.jsx)(t.code,{className:"language-bash",children:"minder profile create -f profile.yaml\n"})}),"\n",(0,r.jsxs)(t.p,{children:["Once the profile is created, Minder will monitor if the ",(0,r.jsx)(t.code,{children:"allow_force_pushes"})," setting on all of your registered\nrepositories is set to ",(0,r.jsx)(t.code,{children:"false"}),". If the setting is set to ",(0,r.jsx)(t.code,{children:"true"}),", Minder will automatically remediate it by disabling it\nand will make sure to keep it that way until the profile is deleted."]}),"\n",(0,r.jsxs)(t.p,{children:["Alerts are complementary to the remediation feature. If you have both ",(0,r.jsx)(t.code,{children:"alert"})," and ",(0,r.jsx)(t.code,{children:"remediation"})," enabled for a profile,\nMinder will attempt to remediate it first. If the remediation fails, Minder will create an alert. If the remediation\nsucceeds, Minder will close any previously opened alerts related to that rule."]}),"\n",(0,r.jsx)(t.h2,{id:"limitations",children:"Limitations"}),"\n",(0,r.jsxs)(t.ul,{children:["\n",(0,r.jsxs)(t.li,{children:["The automatic remediation feature is only available for rule types that support it, i.e., have the ",(0,r.jsx)(t.code,{children:"remediate"})," section defined in their ",(0,r.jsx)(t.code,{children:"<alert-type>.yaml"})," file."]}),"\n"]})]})}function h(e={}){const{wrapper:t}={...(0,n.R)(),...e.components};return t?(0,r.jsx)(t,{...e,children:(0,r.jsx)(c,{...e})}):c(e)}},28453:(e,t,i)=>{i.d(t,{R:()=>o,x:()=>l});var r=i(96540);const n={},a=r.createContext(n);function o(e){const t=r.useContext(a);return r.useMemo((function(){return"function"==typeof e?e(t):{...t,...e}}),[t,e])}function l(e){let t;return t=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:o(e.components),r.createElement(a.Provider,{value:t},e.children)}}}]);