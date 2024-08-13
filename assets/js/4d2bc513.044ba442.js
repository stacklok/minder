"use strict";(self.webpackChunkminder_docs=self.webpackChunkminder_docs||[]).push([[199],{64047:(e,n,i)=>{i.r(n),i.d(n,{assets:()=>d,contentTitle:()=>o,default:()=>c,frontMatter:()=>l,metadata:()=>s,toc:()=>a});var t=i(74848),r=i(28453);const l={sidebar_position:120},o="Using Mindev to develop and debug rule types",s={id:"how-to/mindev",title:"Using Mindev to develop and debug rule types",description:"Mindev is a tool that helps you develop and debug rule types for Minder. It provides a way to run rule types locally and test them against your codebase.",source:"@site/docs/how-to/mindev.md",sourceDirName:"how-to",slug:"/how-to/mindev",permalink:"/how-to/mindev",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:120,frontMatter:{sidebar_position:120},sidebar:"minder",previous:{title:"Writing rules using Rego",permalink:"/how-to/writing-rules-in-rego"},next:{title:"Apply a profile to a subset of entities",permalink:"/how-to/profile_selectors"}},d={},a=[{value:"Prerequisites",id:"prerequisites",level:2},{value:"Build Mindev",id:"build-mindev",level:2},{value:"Run Mindev",id:"run-mindev",level:2},{value:"Linting",id:"linting",level:2},{value:"Running a rule type",id:"running-a-rule-type",level:2},{value:"Entity",id:"entity",level:2},{value:"Authentication",id:"authentication",level:2},{value:"Example",id:"example",level:3},{value:"Rego print",id:"rego-print",level:2},{value:"Conclusion",id:"conclusion",level:2}];function h(e){const n={a:"a",code:"code",h1:"h1",h2:"h2",h3:"h3",header:"header",li:"li",p:"p",pre:"pre",ul:"ul",...(0,r.R)(),...e.components};return(0,t.jsxs)(t.Fragment,{children:[(0,t.jsx)(n.header,{children:(0,t.jsx)(n.h1,{id:"using-mindev-to-develop-and-debug-rule-types",children:"Using Mindev to develop and debug rule types"})}),"\n",(0,t.jsxs)(n.p,{children:[(0,t.jsx)(n.a,{href:"https://github.com/stacklok/minder/tree/main/cmd/dev",children:"Mindev"})," is a tool that helps you develop and debug rule types for Minder. It provides a way to run rule types locally and test them against your codebase."]}),"\n",(0,t.jsx)(n.p,{children:"While it contains more utilities, this guide focuses on using Mindev to develop and debug rule types."}),"\n",(0,t.jsx)(n.h2,{id:"prerequisites",children:"Prerequisites"}),"\n",(0,t.jsxs)(n.ul,{children:["\n",(0,t.jsxs)(n.li,{children:[(0,t.jsx)(n.a,{href:"https://golang.org/doc/install",children:"Go"})," installed on your machine"]}),"\n",(0,t.jsxs)(n.li,{children:[(0,t.jsx)(n.a,{href:"https://cli.github.com/",children:"The gh CLI"})," installed on your machine"]}),"\n"]}),"\n",(0,t.jsx)(n.h2,{id:"build-mindev",children:"Build Mindev"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"make build-mindev\n"})}),"\n",(0,t.jsx)(n.h2,{id:"run-mindev",children:"Run Mindev"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"mindev help\n"})}),"\n",(0,t.jsx)(n.p,{children:"To see the available options for rule types, run:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"mindev ruletype help\n"})}),"\n",(0,t.jsx)(n.h2,{id:"linting",children:"Linting"}),"\n",(0,t.jsx)(n.p,{children:"To lint your rule type, run:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"mindev ruletype lint -f path/to/rule-type.yaml\n"})}),"\n",(0,t.jsx)(n.h2,{id:"running-a-rule-type",children:"Running a rule type"}),"\n",(0,t.jsx)(n.p,{children:"To run a rule type, use the following command:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"mindev ruletype test -e mindev ruletype test -e /path/to/entity -p /path/to/profile -r /path/to/rule\n"})}),"\n",(0,t.jsx)(n.p,{children:"Where the flags are:"}),"\n",(0,t.jsxs)(n.ul,{children:["\n",(0,t.jsxs)(n.li,{children:[(0,t.jsx)(n.code,{children:"-e"})," or ",(0,t.jsx)(n.code,{children:"--entity"}),": The path to the entity file"]}),"\n",(0,t.jsxs)(n.li,{children:[(0,t.jsx)(n.code,{children:"-p"})," or ",(0,t.jsx)(n.code,{children:"--profile"}),": The path to the profile file"]}),"\n",(0,t.jsxs)(n.li,{children:[(0,t.jsx)(n.code,{children:"-r"})," or ",(0,t.jsx)(n.code,{children:"--rule"}),": The path to the rule file"]}),"\n"]}),"\n",(0,t.jsx)(n.p,{children:"The entity could be the repository or the codebase you want to test the rule type against."}),"\n",(0,t.jsx)(n.p,{children:"The rule is the rule type definition you want to verify"}),"\n",(0,t.jsx)(n.p,{children:"And the profile is needed so we can specify the parameters and definitions for the rule type."}),"\n",(0,t.jsx)(n.h2,{id:"entity",children:"Entity"}),"\n",(0,t.jsx)(n.p,{children:"An entity in minder is the target in the supply chain that minder is evaluating. In some cases, it may\nbe the repository. Minder the minimal information needed to evaluate the rule type."}),"\n",(0,t.jsx)(n.p,{children:"The values needed must match an entity's protobuf definition. for instance, for a repository entity, the following fields are required:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:"---\nname: <name of the repo>\nowner: <owner of the repo>\nrepo_id: <upstream ID>\nclone_url: <clone URL>\ndefault_branch: <default branch>\n"})}),"\n",(0,t.jsx)(n.p,{children:"Minder is able to use these values to check the current state of the repository and evaluate the rule type."}),"\n",(0,t.jsx)(n.h2,{id:"authentication",children:"Authentication"}),"\n",(0,t.jsx)(n.p,{children:"If the rule type requires authentication, you can use the following environment variable:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"export AUTH_TOKEN=your_token\n"})}),"\n",(0,t.jsx)(n.h3,{id:"example",children:"Example"}),"\n",(0,t.jsxs)(n.p,{children:["Let's evaluate if the ",(0,t.jsx)(n.code,{children:"minder"})," repository has set up dependabot for golang dependencies correctly."]}),"\n",(0,t.jsxs)(n.p,{children:["We can get the necessary rule type from the ",(0,t.jsx)(n.a,{href:"https://github.com/stacklok/minder-rules-and-profiles",children:"minder rules and profiles repo"}),"."]}),"\n",(0,t.jsxs)(n.p,{children:["We'll create a file called ",(0,t.jsx)(n.code,{children:"entity.yaml"})," with the following content:"]}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:"---\nname: minder\nowner: stacklok\nrepo_id: 624056558\nclone_url: https://github.com/stacklok/minder.git\ndefault_branch: main\n"})}),"\n",(0,t.jsx)(n.p,{children:"We'll use the readily available profile for dependabot for golang dependencies:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-yaml",children:'---\n# Simple profile showing off the dependabot_configured rule\nversion: v1\ntype: profile\nname: dependabot-go-github-profile\ndisplay_name: Dependabot for Go projects\ncontext:\n  provider: github\nalert: "on"\nremediate: "off"\nrepository:\n  - type: dependabot_configured\n    def:\n      package_ecosystem: gomod\n      schedule_interval: daily\n      apply_if_file: go.mod\n'})}),"\n",(0,t.jsxs)(n.p,{children:["This is already available in the ",(0,t.jsx)(n.a,{href:"https://github.com/stacklok/minder-rules-and-profiles/blob/main/profiles/github/dependabot_go.yaml",children:"minder rules and profiles repo"}),"."]}),"\n",(0,t.jsx)(n.p,{children:"Let's set up authentication:"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"export AUTH_TOKEN=$(gh auth token)\n"})}),"\n",(0,t.jsx)(n.p,{children:"Let's give it a try!"}),"\n",(0,t.jsx)(n.pre,{children:(0,t.jsx)(n.code,{className:"language-bash",children:"$ mindev ruletype test -e repo.yaml -p profiles/github/dependabot_go.yaml -r rule-types/github/dependabot_configured.yaml\nProfile valid according to the JSON schema!\nThe rule type is valid and the entity conforms to it\n"})}),"\n",(0,t.jsxs)(n.p,{children:["The output shows that the rule type is valid and the entity conforms to it. Meaning the ",(0,t.jsx)(n.code,{children:"minder"})," repository has set up dependabot for golang dependencies correctly."]}),"\n",(0,t.jsx)(n.h2,{id:"rego-print",children:"Rego print"}),"\n",(0,t.jsxs)(n.p,{children:["Mindev also has the necessary pieces set up so you can debug your rego rules. e.g. ",(0,t.jsx)(n.code,{children:"print"})," statements\nin rego will be printed to the console."]}),"\n",(0,t.jsxs)(n.p,{children:["For more information on the rego print statement, the following blog post is a good resource: ",(0,t.jsx)(n.a,{href:"https://blog.openpolicyagent.org/introducing-the-opa-print-function-809da6a13aee",children:"Introducing the OPA print function"})]}),"\n",(0,t.jsx)(n.h2,{id:"conclusion",children:"Conclusion"}),"\n",(0,t.jsx)(n.p,{children:"Mindev is a powerful tool that helps you develop and debug rule types for Minder. It provides a way to run rule types locally and test them against your codebase."})]})}function c(e={}){const{wrapper:n}={...(0,r.R)(),...e.components};return n?(0,t.jsx)(n,{...e,children:(0,t.jsx)(h,{...e})}):h(e)}},28453:(e,n,i)=>{i.d(n,{R:()=>o,x:()=>s});var t=i(96540);const r={},l=t.createContext(r);function o(e){const n=t.useContext(l);return t.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function s(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(r):e.components||r:o(e.components),t.createElement(l.Provider,{value:n},e.children)}}}]);