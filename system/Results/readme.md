# GNN Explainer Output Documentation

## Overview

This README provides guidance on interpreting the output visualizations produced by the Graph Neural Network (GNN) explainer. The explainer is designed to illustrate the connections within the graph that are most influential in the model's classification decisions.

## Visualization Details

### Node Highlighting

- **Target Node:** The target node, which is the primary focus of the explanation, is highlighted in red. This coloring is used to easily identify the node whose classification decision is being explained by the GNN model.

### Edge Highlighting

- **Important Edges:** Edges that are crucial in influencing the classification decision of the target node are also highlighted in red. These edges represent important connections that have a significant impact on the model's output, providing insights into the relational dynamics considered by the model.

### Storage of Explainer Graphs

The explainer graphs are stored in the following directories:
- **OpTC Day1**
- **OpTC Day2**
- **OpTC Day3**

Each directory represents some of the sample graphs extracted from the respective dataset evaluation day, helping to organize the output according to the timeline of data processing.
The graphs are stored as html files and can be visualized in a browser.
