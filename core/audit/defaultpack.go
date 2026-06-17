// SPDX-License-Identifier: MIT

package audit

// pipelineGlobs are the common CI/CD pipeline definition locations across
// GitHub Actions, Azure Pipelines, GitLab CI, Jenkins, and Bitbucket.
var pipelineGlobs = []string{
	".github/workflows/*.yml", ".github/workflows/*.yaml",
	"azure-pipelines.yml", "azure-pipelines.yaml", "**/azure-pipelines*.yml",
	".gitlab-ci.yml", "Jenkinsfile", "**/Jenkinsfile",
	"bitbucket-pipelines.yml", "buildkite.yml", ".buildkite/*.yml",
}

// DefaultRuleSet returns Wake's built-in policy pack: a generic
// reproduction of the common repository control audit — CI/CD presence,
// unit-test execution, code-quality gate, and deployment intent.
//
// Applicability is driven by repository classification (e.g. unit tests do
// not apply to a docs or GitOps repo) rather than the name-based exclusions
// and manual false-positive exception lists the original audit relied on —
// the principled replacement per DECISIONS/0004.
func DefaultRuleSet() RuleSet {
	return RuleSet{
		Name:    "wake-default",
		Version: "v1",
		Controls: []Control{
			{
				ID: "ci-pipeline", Title: "CI/CD pipeline present", Kind: KindBoolean, Severity: Hard,
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs}},
				Evidence:    []EvidencePattern{{PathGlobs: pipelineGlobs, Description: "a recognized CI/CD pipeline definition exists"}},
				Remediation: "Add a CI pipeline (e.g. a .github/workflows job) that builds and tests the repository.",
			},
			{
				ID: "unit-tests", Title: "Unit tests run in CI", Kind: KindBoolean, Severity: Hard,
				Requires:    []string{"ci-pipeline"},
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs, ArchetypeGitOps, ArchetypeIaC}},
				Evidence: []EvidencePattern{
					{
						PathGlobs: pipelineGlobs,
						ContentPatterns: []string{
							`(?i)\b(go test|npm( run)? test|yarn test|pytest|dotnet test|mvn(\s+\S+)*\s+test|gradle(w)?\s+\S*test|jest|vitest|nunit|xunit)\b`,
							`(?i)testResultsFormat|unit ?tests?\b`,
						},
						Description: "the pipeline invokes a test runner",
					},
					{
						PathGlobs: []string{
							"**/*_test.go", "**/*.Tests.csproj", "**/*.Test.csproj",
							"**/*.test.ts", "**/*.spec.ts", "**/*.test.js", "**/*.spec.js",
							"**/test_*.py", "**/*_test.py",
						},
						Description: "test project/source files are present",
					},
				},
				Remediation: "Add a unit-test stage to the pipeline (and tests if missing).",
			},
			{
				ID: "quality-gate", Title: "Code-quality gate (SonarQube/equivalent)", Kind: KindBoolean, Severity: Soft,
				Requires:    []string{"ci-pipeline"},
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs, ArchetypeGitOps, ArchetypeIaC}},
				Evidence: []EvidencePattern{
					{
						PathGlobs: pipelineGlobs,
						ContentPatterns: []string{
							`(?i)sonar-scanner|SonarQube(Prepare|Analyze|Publish)|sonar\.projectKey|sonar\.host\.url`,
							`(?i)codeql|codacy|coverity`,
						},
						Description: "the pipeline runs a code-quality scan",
					},
					{PathGlobs: []string{"sonar-project.properties", "**/sonar-project.properties"}, Description: "a SonarQube project config is present"},
				},
				Remediation: "Integrate a code-quality gate (SonarQube or equivalent) into the pipeline.",
			},
			{
				ID: "deployment-intent", Title: "Deployment intent", Kind: KindCategorical, Severity: Soft,
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs}},
				Categories: []Category{
					{
						Name: "production",
						Evidence: []EvidencePattern{{
							PathGlobs:       pipelineGlobs,
							ContentPatterns: []string{`(?i)environment:\s*['"]?prod`, `(?i)\bdeploy\b.*\bprod`, `(?i)kind:\s*Deployment`},
						}},
					},
					{
						Name: "non-production",
						Evidence: []EvidencePattern{{
							PathGlobs:       pipelineGlobs,
							ContentPatterns: []string{`(?i)environment:`, `(?i)\bdeploy\b`},
						}},
					},
				},
				DefaultCategory: "unknown",
			},
		},
	}
}
