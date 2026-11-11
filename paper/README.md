# QTFuzz: Academic Research Paper (`paper/`)

This directory contains the complete LaTeX source code, figures, tables, bibliography, and verification scripts for our research paper:

> **Title:** *Cross-Domain Fuzzing Through Structure-Aware Mutation and Bandit-Guided Adaptation*  
> **Authors:** Dakshin, Neel, Samyak (Indian Institute of Technology Guwahati)  
> **Target Venue:** ACM International Conference on Foundations of Software Engineering (FSE) / ACM Small Format  
> **Course:** CS-5187 Advanced Software Engineering Term Project  
> **Compiled PDF:** 📄 **[View / Download `main.pdf`](main.pdf)** (12-page ACM single-column format)  

---

## Directory Organization

```text
paper/
├── main.tex                   # Master LaTeX document
├── macros.tex                 # Mathematical notation, tool names (\tool -> QTFuzz), macros
├── paper.conf                 # Conference and page-limit configuration
├── Makefile                   # Automation Makefile (all, clean, check)
├── ACM-Reference-Format.bst   # ACM official BibTeX bibliography style
├── acmart.cls                 # ACM conference LaTeX class
│
├── sections/                  # Modular paper content sections
│   ├── abstract.tex           # Abstract (200 words)
│   ├── introduction.tex       # Section 1: Intro & Motivating Examples
│   ├── background.tex         # Section 2: Coverage Fuzzing & MAB Preliminaries
│   ├── problem.tex            # Section 3: Cross-Domain Impedance Mismatches
│   ├── approach.tex           # Section 4: Architecture, MAB Scheduling & Headless Shims
│   ├── evaluation.tex         # Section 5: Empirical Evaluation (807M execs, RQ1-RQ4)
│   ├── discussion.tex         # Section 6: Lessons Learned & Engineering Trade-offs
│   ├── threats.tex            # Section 7: Threats to Validity
│   ├── related.tex            # Section 8: Related Work
│   ├── conclusion.tex         # Section 9: Concluding Remarks
│   └── data.tex               # Data & Artifact Availability Statement
│
├── figures/                   # High-resolution TikZ vector figures
│   ├── overview.tex           # Figure 2: Unified 3-stage extension architecture
│   └── subsystems.tex         # Figure 3: Headless raylib & in-memory drogon cards
│
├── tables/                    # LaTeX tables
│   ├── subjects.tex           # Table 1: Subject systems, harnesses & executions
│   └── findings.tex           # Table 2: Verified upstream security defects & status
│
├── references.bib             # Verified BibTeX citations & upstream GitHub issues/PRs
└── scripts/
    └── check.sh               # Strict 12-page ceiling & lint validation script
```

---

## Building the Paper

Building the paper requires a standard TeX Live distribution (`pdflatex`, `bibtex`):

```bash
# On Ubuntu / Debian:
sudo apt-get install -y texlive-latex-extra texlive-fonts-recommended texlive-bibtex-extra

# Build PDF:
make
# or
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

---

## Automated Validation & Verification

Run `bash scripts/check.sh` to enforce all conference and course constraints:
- **0 LaTeX compilation errors**
- **0 `\todo` comments**
- **0 numerical placeholders (`\num{}`)**
- **Strict 12-page ceiling** (References start on or before page 12)
- **Zero banned words / colloquialisms**

```bash
bash scripts/check.sh
```

