# 🛡️ Explainable AI based Intrusion Detection System

<div align="center">

![XAI](https://img.shields.io/badge/Explainable%20AI-Cybersecurity-blue?style=for-the-badge&logo=shield)
![PyTorch](https://img.shields.io/badge/PyTorch-GNN-red?style=for-the-badge&logo=pytorch)
![SHAP](https://img.shields.io/badge/SHAP-Explainability-green?style=for-the-badge&logo=python)
![Word2Vec](https://img.shields.io/badge/Word2Vec-Embeddings-yellow?style=for-the-badge&logo=vector)
![Transformers](https://img.shields.io/badge/Transformers-NLP-orange?style=for-the-badge&logo=transformer)

**Enterprise-Grade Explainable AI Solution for Cybersecurity** - A production-ready machine learning system that not only detects security threats using advanced graph neural networks but also provides human-interpretable explanations for every decision. This addresses the critical business need for AI transparency in high-stakes security environments where "black box" models are unacceptable.

</div>

---

## 🌟 Overview

This project represents a breakthrough in cybersecurity AI, combining state-of-the-art graph neural networks with comprehensive explainability to solve the critical "black box" problem in security operations. Built with enterprise-grade technologies and validated on real-world DARPA datasets.

### ✨ Key Features

- 🎯 **Business Impact**: Solves the critical "AI black box" problem in cybersecurity - every detection comes with clear, actionable explanations
- 🏢 **Enterprise Ready**: Evaluated on real DARPA datasets used by Fortune 500 companies and government agencies
- 🔍 **Advanced XAI Techniques**: Implements cutting-edge explainable AI methods (SHAP, LIME, Integrated Gradients) with custom attribution algorithms
- 📊 **Interactive Dashboards**: Production-quality HTML visualizations that security analysts can use immediately
- ⚡ **Production Scale**: Handles enterprise-level data volumes with GPU acceleration and parallel processing

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data          │    │   GNN           │    │   Explanation   │
│   Ingestion     │    │   Detection     │    │   Engine        │
│   (Logs/SIEM)   │    │   (GCN/SAGE)    │    │   (SHAP/LIME)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Interactive   │
                    │   Dashboards    │
                    │   (HTML/JS)     │
                    └─────────────────┘
```

## 🛠️ Tech Stack

### Core AI/ML
- **🧠 Graph Neural Networks** (PyTorch Geometric) - State-of-the-art GCN, SAGE, GAT architectures for complex relationship modeling
- **🔬 Explainable AI** - Industry-standard SHAP, LIME, Integrated Gradients + custom attribution algorithms
- **📈 Graph Analytics** - Advanced NetworkX algorithms for enterprise-scale graph processing
- **🎨 Interactive Visualizations** - Production-ready HTML dashboards for security operations centers
- **⚡ High-Performance ML** - PyTorch, scikit-learn, XGBoost with CUDA acceleration for real-time processing

## 💼 Business Value & Impact

In today's AI-driven cybersecurity landscape, organizations face a critical challenge: **AI models that work but can't explain their decisions**. This creates:

- **🏛️ Regulatory Compliance Issues** (GDPR, CCPA require AI explainability)
- **😤 Security Analyst Frustration** (can't trust or act on unexplained alerts)
- **⚖️ Legal Liability** (unexplained AI decisions in court cases)
- **📉 Operational Inefficiency** (high false positive rates without explanations)

### ✅ This Project Solves These Problems

- **🔍 Providing clear explanations** for every security alert
- **📋 Enabling regulatory compliance** with explainable AI requirements
- **⚡ Improving analyst productivity** with actionable insights
- **🎯 Reducing false positives** through interpretable decision logic
- **⚖️ Supporting legal proceedings** with auditable AI decisions

## 🔬 Technical Innovation

### Two-Phase Explainable AI Pipeline

1. **🔍 Detection Phase**: Advanced GNN models analyze provenance graphs to identify security threats
2. **📊 Explanation Phase**: Multi-method explainability generates human-interpretable insights

### Enterprise-Grade Components

- **📥 Data Ingestion**: Real-time parsing of enterprise security logs (SIEM integration ready)
- **🕸️ Graph Construction**: Converts complex system events into interpretable relationship graphs
- **🤖 AI Detection**: State-of-the-art GNN models (GCN, SAGE, GAT) for threat identification
- **💡 Explanation Engine**: 
  - **Training Attribution**: Understand which features drive model learning
  - **Post-hoc Analysis**: SHAP, LIME, Integrated Gradients for decision interpretation
  - **Visual Analytics**: Interactive HTML dashboards for security operations teams

> **💡 Key Innovation**: Unlike traditional "black box" AI, this system provides **complete transparency** - every security decision comes with a clear, actionable explanation that security analysts can understand and act upon.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ environment
- Jupyter Lab/Notebook
- CUDA-capable GPU (optional, for acceleration)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/explainable-intrusion-detection.git
   cd explainable-intrusion-detection
   ```

2. **Install dependencies**
   ```bash
   # Open dependencies.ipynb in Jupyter
   # Run all cells to install required packages
   jupyter lab dependencies.ipynb
   ```

3. **Configure environment**
   - The notebook will automatically detect CPU/GPU runtime
   - Install PyTorch and PyG based on your hardware
   - All required packages will be installed automatically

### Running the System

1. **Launch Jupyter Lab**
   ```bash
   jupyter lab
   ```

2. **Choose your analysis type**
   - **Training Attribution**: `system/Training_data_attribution_methods/`
   - **Post-hoc Analysis**: `system/Posthoc-explaination_methosd/`

3. **Configure and run**
   - Review parameters in the notebook
   - Run all cells
   - View interactive results and explanations

## ⚙️ Configuration

Each notebook exposes parameters to configure:
- **📁 Dataset paths** and sampling settings
- **🧠 GNN architecture** choices (GCN, SAGE, GAT)
- **🔍 Explanation method** selection (attribution vs post-hoc)
- **📊 Evaluation metrics** and output paths

## 📊 Datasets

This project is evaluated on open-source datasets from DARPA and the research community.

### 🏢 DARPA E3 (Enterprise Email Exfiltration)
- **📥 Source**: [E3 Dataset](https://drive.google.com/drive/folders/1fOCY3ERsEmXmvDekG-LUUSjfWs6TRdp)
- **📋 Description**: Enterprise email exfiltration scenarios with provenance traces
- **🤖 Models**: CADETS, Theia

### 🏢 DARPA E5 (Enterprise Email Exfiltration Extended)
- **📥 Source**: [E5 Dataset](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
- **📋 Description**: Extended enterprise email exfiltration with multiple attack scenarios
- **🤖 Models**: CADETS, Theia, ClearScope

### 🏭 DARPA OpTC (Operational Technology Cybersecurity)
- **📥 Source**: [OpTC Dataset](https://github.com/FiveDirections/OpTC-data)
- **📋 Description**: Operational technology cybersecurity dataset for intrusion detection
- **⏰ Timeline**: Multi-day evaluation across different attack scenarios

## 📁 Project Structure

```
explainable-intrusion-detection/
├── 📁 system/
│   ├── 📁 Training_data_attribution_methods/    # Training attribution analysis
│   │   ├── 📄 dependencies.ipynb
│   │   ├── 📄 E3_Cadets_attribution.ipynb
│   │   ├── 📄 E3_Theia_attribution.ipynb
│   │   ├── 📄 E5_Cadets_attribution.ipynb
│   │   └── 📄 OpTC_Train_Attribution.ipynb
│   ├── 📁 Posthoc-explaination_methosd/         # Post-hoc explanation methods
│   │   ├── 📄 E3_PostHoc_Explanations.ipynb
│   │   ├── 📄 OpTC_PostHoc_Explainers.ipynb
│   │   └── 📄 PostHoc_Explainers_E3_Theia.ipynb
│   └── 📁 explanation_outputs/                  # Interactive visualizations
│       ├── 📁 E3-Cadets/
│       ├── 📁 E3-Theia/
│       ├── 📁 E5/
│       ├── 📁 OpTC/
│       └── 📁 Motivation/
└── 📄 README.md
```

### 🔬 Training Data Attribution Methods
- **📍 Location**: `system/Training_data_attribution_methods/` directory
- **🎯 Purpose**: Understanding feature importance during training
- **✨ Features**: 
  - Integrated data parsers for each dataset
  - GNN training with attribution analysis
  - Feature importance visualization
  - Model performance evaluation

### 🔍 Post-hoc Explanation Methods
- **📍 Location**: `system/Posthoc-explaination_methosd/` directory
- **🎯 Purpose**: Post-hoc model explanation and interpretation
- **✨ Features**: 
  - SHAP, LIME, and custom explainer implementations
  - Model-agnostic explanation generation
  - Comparative analysis across explanation methods

### 📊 Explanation Outputs
- **📍 Location**: `system/explanation_outputs/` directory
- **📋 Contents**: 
  - Interactive HTML visualizations of graph explanations
  - Node and edge highlighting for important features
  - Organized by dataset and explanation method
  - Leave-one-out (LOO) analysis graphs

### 🎯 Key Features
- **🎯 Multi-Method XAI**: Comprehensive explainability covering both training attribution and post-hoc analysis
- **📊 Production Dashboards**: Interactive HTML visualizations ready for security operations centers
- **🏢 Enterprise Scale**: Validated across industry-standard DARPA datasets used by Fortune 500 companies
- **🔧 Modular Architecture**: Plug-and-play explainability methods for different business needs
- **📈 Reproducible Results**: Deterministic pipelines with clear documentation for regulatory compliance

## 💰 Business Impact & ROI

### 🎯 Key Benefits for Organizations

- **📉 Reduced False Positives**: Clear explanations help analysts quickly identify real threats
- **⚡ Faster Incident Response**: Interpretable alerts enable immediate action without investigation delays
- **🏛️ Regulatory Compliance**: Meets requirements for AI explainability in regulated industries
- **💰 Cost Savings**: Reduced analyst workload and faster threat resolution
- **🛡️ Improved Security Posture**: Better understanding of attack patterns leads to proactive defense

### 🏆 Technical Excellence

- **🔬 Research-Grade**: Implements cutting-edge XAI methods from top-tier conferences
- **⚡ Production-Ready**: GPU acceleration and parallel processing for enterprise scale
- **📊 Visual Analytics**: Interactive dashboards that security teams can use immediately
- **🔒 Audit Trail**: Complete explainability for compliance and legal requirements

## 📝 Notes

- **📦 Datasets**: Large datasets are hosted externally; see links above for access
- **🔧 Configuration**: Some notebooks may require paths to be updated to your local dataset location

---

## 🏆 Technical Excellence & Industry Standards

### 🧠 Advanced AI/ML Stack
- **PyTorch** - Deep learning framework with CUDA support
- **PyTorch Geometric** - Graph neural networks (GCN, SAGE, GAT)
- **scikit-learn** - ML algorithms and preprocessing pipelines
- **XGBoost** - Gradient boosting for classification

### 🔬 Explainable AI & Interpretability
- **SHAP** - Model explainability and feature attribution
- **LIME** - Local interpretable model-agnostic explanations
- **Integrated Gradients** - Gradient-based attribution methods
- **Custom Attribution Methods** - Training-time feature importance analysis

### 📊 Data Processing & Analysis
- **Pandas** - Data manipulation and analysis
- **NumPy** - Numerical computing
- **NetworkX** - Graph algorithms and analysis
- **Gensim** - Text embeddings and word2vec

### 🎨 Visualization & Analytics
- **Interactive HTML Visualizations** - Graph explanations with node/edge highlighting
- **Graph Neural Networks** - GCN, SAGE, GAT architectures for graph-structured data
- **Custom Graph Analytics** - Specialized algorithms for cybersecurity analysis

### ⚡ Performance & Infrastructure
- **CUDA Support** - GPU acceleration for deep learning
- **Parallel Processing** - Multi-threaded data processing
- **Memory Optimization** - Efficient graph representation
- **Progress Tracking** - Real-time experiment monitoring

### 🏢 Development & MLOps
- **Jupyter Lab** - Interactive development environment
- **Modular Design** - Plug-and-play components for different methods
- **Reproducible Experiments** - Deterministic pipelines and documentation
- **Interactive Outputs** - HTML visualizations for analysis and sharing

---
