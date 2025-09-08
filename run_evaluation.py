#!/usr/bin/env python3
"""
Batch evaluation runner: iterates datasets (4k/6k/50k/120k/200k), runs AdvancedEvaluationPipeline,
and saves metrics/figures per dataset into results/<name>/.
"""

import os
import sys
from datetime import datetime
from typing import List

try:
    from evaluation_pipeline import AdvancedEvaluationPipeline
except Exception as e:
    print(f"❌ Could not import AdvancedEvaluationPipeline: {e}")
    sys.exit(1)


def run_for_dataset(dataset_path: str, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    print(f"\n🚀 Running evaluation for {dataset_path} -> {output_dir}")
    pipe = AdvancedEvaluationPipeline(dataset_path)
    all_results = pipe.run_evaluation()
    metrics = pipe.print_results(all_results)
    fig = pipe.create_visualizations(all_results, metrics)
    # Save CSVs
    pipe.save_detailed_results(all_results, metrics)
    # Move generated files into output_dir for organization
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Collect most recent generated files created by save_detailed_results/create_visualizations
    for fname in os.listdir('.'):
        if fname.startswith('evaluation_metrics_') or fname.startswith('detailed_results_') or fname.startswith('evaluation_results_'):
            try:
                os.replace(fname, os.path.join(output_dir, fname))
            except Exception:
                pass
    print(f"✅ Saved results to {output_dir}")


def main() -> None:
    base_data_dir = os.path.join('data')
    datasets: List[str] = [
        os.path.join(base_data_dir, '4kdata.json'),
        os.path.join(base_data_dir, '6kdata.json'),
        os.path.join(base_data_dir, '50kdata.json'),
        os.path.join(base_data_dir, '120kdata.json'),
        os.path.join(base_data_dir, '200kdata.json'),
    ]
    for ds in datasets:
        if not os.path.exists(ds):
            print(f"⚠️ Missing dataset: {ds} — skipping")
            continue
        name = os.path.splitext(os.path.basename(ds))[0]
        out = os.path.join('results', name)
        run_for_dataset(ds, out)
    print("\n🎉 Batch evaluation complete. See results/<dataset>/ for outputs.")


if __name__ == '__main__':
    main()

    @staticmethod
    def _plot_confusion_matrix_enhanced(y_true, y_pred, labels, output_dir: str):
        """Generate enhanced confusion matrix plot with beautiful colors"""
        try:
            from collections import Counter
            # Build confusion counts
            index = {label: i for i, label in enumerate(labels)}
            size = len(labels)
            cm = [[0 for _ in range(size)] for _ in range(size)]
            for yt, yp in zip(y_true, y_pred):
                if yt in index and yp in index:
                    cm[index[yt]][index[yp]] += 1

            # Create enhanced confusion matrix
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Use custom colormap for better visualization
            colors = ['#f7f7f7', '#d1e5c0', '#92c5de', '#4393c3', '#2166ac']
            n_bins = 100
            cmap = LinearSegmentedColormap.from_list("custom", colors, N=n_bins)
            
            im = ax.imshow(cm, interpolation='nearest', cmap=cmap, aspect='auto')
            ax.set_title('Confusion Matrix', fontsize=16, fontweight='bold', color='#2c3e50', pad=20)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax, shrink=0.8)
            cbar.set_label('Count', fontweight='bold')
            
            tick_marks = range(len(labels))
            ax.set_xticks(tick_marks)
            ax.set_yticks(tick_marks)
            ax.set_xticklabels(labels, rotation=45, ha='right')
            ax.set_yticklabels(labels)
            
            # Annotate with enhanced styling
            for i in range(size):
                for j in range(size):
                    color = 'white' if cm[i][j] > max(max(row) for row in cm) / 2 else 'black'
                    ax.text(j, i, str(cm[i][j]), ha='center', va='center', 
                           color=color, fontweight='bold', fontsize=12)
            
            ax.set_ylabel('Actual Label', fontweight='bold', fontsize=12)
            ax.set_xlabel('Predicted Label', fontweight='bold', fontsize=12)
            
            # Add grid for better readability
            ax.grid(False)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'confusion_matrix_enhanced.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated enhanced confusion matrix plot")
        except Exception as e:
            print(f"⚠️ Could not generate enhanced confusion matrix: {e}")

    @staticmethod
    def _plot_latency_enhanced(latency: dict, output_dir: str):
        """Generate enhanced latency comparison plot with beautiful colors"""
        try:
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Use custom colors for latency bars
            colors = PlotGenerator.BAR_COLORS['latency']
            methods = list(latency.keys())
            values = list(latency.values())
            
            # Create gradient effect by varying alpha
            bars = ax.bar(methods, values, color=colors[:len(methods)], 
                         alpha=0.8, edgecolor='white', linewidth=2)
            
            ax.set_title('Latency Comparison', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            ax.set_ylabel('Latency (ms)', fontweight='bold', fontsize=12)
            ax.set_xlabel('Detection Methods', fontweight='bold', fontsize=12)
            ax.set_xticklabels(methods, rotation=45, ha='right')
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + max(values) * 0.01,
                       f'{value:.1f}ms', ha='center', va='bottom', fontweight='bold')
            
            # Enhanced grid
            ax.grid(True, alpha=0.3, linestyle='--', color='#bdc3c7')
            ax.set_axisbelow(True)
            
            # Set y-axis to start from 0
            ax.set_ylim(0, max(values) * 1.1)
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'latency_comparison_enhanced.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated enhanced latency comparison plot")
        except Exception as e:
            print(f"⚠️ Could not generate enhanced latency plot: {e}")

    @staticmethod
    def _plot_method_distribution_pie(metrics: dict, output_dir: str):
        """Generate beautiful pie chart showing method distribution"""
        try:
            # Calculate average performance for each method
            method_scores = {}
            for method, data in metrics.items():
                avg_score = (data.get('accuracy', 0) + data.get('precision', 0) + 
                           data.get('recall', 0) + data.get('f1', 0)) / 4
                method_scores[method] = avg_score
            
            # Sort by performance
            sorted_methods = sorted(method_scores.items(), key=lambda x: x[1], reverse=True)
            methods, scores = zip(*sorted_methods)
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Use custom colors
            colors = PlotGenerator.PIE_COLORS[:len(methods)]
            
            # Create pie chart with enhanced styling
            wedges, texts, autotexts = ax.pie(scores, labels=methods, autopct='%1.1f%%',
                                             colors=colors, startangle=90, 
                                             wedgeprops={'edgecolor': 'white', 'linewidth': 2})
            
            # Enhance text styling
            for text in texts:
                text.set_fontweight('bold')
                text.set_fontsize(11)
            
            for autotext in autotexts:
                autotext.set_fontweight('bold')
                autotext.set_color('white')
                autotext.set_fontsize(10)
            
            ax.set_title('Method Performance Distribution', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            
            # Add legend
            legend_elements = [mpatches.Patch(color=color, label=f'{method}: {score:.3f}')
                             for method, score, color in zip(methods, scores, colors)]
            ax.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0, 0.5, 1))
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'method_distribution_pie.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated method distribution pie chart")
        except Exception as e:
            print(f"⚠️ Could not generate pie chart: {e}")

    @staticmethod
    def _plot_performance_trends(metrics: dict, output_dir: str):
        """Generate line chart showing performance trends across methods"""
        try:
            # Prepare data for line chart
            methods = list(metrics.keys())
            metrics_list = ['accuracy', 'precision', 'recall', 'f1']
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Use custom line colors
            colors = PlotGenerator.LINE_COLORS[:len(metrics_list)]
            
            # Plot each metric as a line
            for i, metric in enumerate(metrics_list):
                values = [metrics[method].get(metric, 0) for method in methods]
                ax.plot(methods, values, marker='o', linewidth=3, markersize=8,
                       color=colors[i], label=metric.title(), alpha=0.8)
            
            ax.set_title('Performance Trends Across Methods', fontsize=16, fontweight='bold', 
                        color='#2c3e50', pad=20)
            ax.set_xlabel('Detection Methods', fontweight='bold', fontsize=12)
            ax.set_ylabel('Score', fontweight='bold', fontsize=12)
            ax.set_xticklabels(methods, rotation=45, ha='right')
            
            # Enhanced grid and styling
            ax.grid(True, alpha=0.3, linestyle='--', color='#bdc3c7')
            ax.set_axisbelow(True)
            ax.set_ylim(0, 1.1)
            
            # Add legend
            ax.legend(loc='upper right', framealpha=0.9, fancybox=True, shadow=True)
            
            # Add value labels on points
            for method_idx, method in enumerate(methods):
                for metric_idx, metric in enumerate(metrics_list):
                    value = metrics[method].get(metric, 0)
                    ax.annotate(f'{value:.3f}', 
                               (method_idx, value),
                               textcoords="offset points",
                               xytext=(0, 10),
                               ha='center',
                               fontsize=9,
                               fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'performance_trends_line.png'), 
                       dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            print("✓ Generated performance trends line chart")
        except Exception as e:
            print(f"⚠️ Could not generate line chart: {e}")


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='Run ZKP LLM evaluation')
    parser.add_argument('--dataset', '-d', type=str, help='Dataset path')
    parser.add_argument('--output', '-o', type=str, default='results',
                        help='Output directory')
    args = parser.parse_args()

    # Setup output directory
    os.makedirs(args.output, exist_ok=True)

    # Run evaluation
    print("🚀 Running evaluation...")
    
    if AdvancedEvaluationPipeline is None:
        print("❌ AdvancedEvaluationPipeline not available. Creating sample data for visualization demo...")
        # Create sample data for visualization demo
        all_results = {
            'ZKP Framework': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 2 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 2 == 0 else 'adversarial',
                    'confidence': 0.8 + (i * 0.1) % 0.2,
                    'detection_time': 0.045 + (i * 0.01) % 0.02
                })() for i in range(100)
            ],
            'Regex Baseline': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 3 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 3 == 0 else 'adversarial',
                    'confidence': 0.7 + (i * 0.1) % 0.3,
                    'detection_time': 0.013 + (i * 0.001) % 0.005
                })() for i in range(100)
            ],
            'Semantic Classifier': [
                type('DetectionResult', (), {
                    'true_label': 'safe' if i % 4 == 0 else 'adversarial',
                    'predicted_label': 'safe' if i % 4 == 0 else 'adversarial',
                    'confidence': 0.85 + (i * 0.1) % 0.15,
                    'detection_time': 0.157 + (i * 0.01) % 0.02
                })() for i in range(100)
            ]
        }
    else:
        pipeline = AdvancedEvaluationPipeline(args.dataset)
        # Get raw results per method
        all_results = pipeline.run_evaluation()

    if not all_results:
        print("❌ No results returned from evaluation!")
        sys.exit(1)

    # Compute metrics per method
    if AdvancedEvaluationPipeline is not None:
        metrics = {method: pipeline.calculate_metrics(results)
                   for method, results in all_results.items()}
    else:
        # Simple metrics calculation for demo
        metrics = {}
        for method, results in all_results.items():
            total = len(results)
            correct = sum(1 for r in results if r.true_label == r.predicted_label)
            accuracy = correct / total if total > 0 else 0
            
            # Simple precision/recall calculation
            true_positives = sum(1 for r in results if r.true_label == 'adversarial' and r.predicted_label == 'adversarial')
            predicted_positives = sum(1 for r in results if r.predicted_label == 'adversarial')
            actual_positives = sum(1 for r in results if r.true_label == 'adversarial')
            
            precision = true_positives / predicted_positives if predicted_positives > 0 else 0
            recall = true_positives / actual_positives if actual_positives > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            avg_time = sum(r.detection_time for r in results) / total if total > 0 else 0
            
            metrics[method] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'avg_detection_time': avg_time
            }

    # Build confusion matrix from ZKP Framework results
    zkp_results = all_results.get('ZKP Framework', [])
    y_true = [r.true_label for r in zkp_results]
    y_pred = [r.predicted_label for r in zkp_results]
    labels = ['safe', 'adversarial']

    # Build latency dict (ms)
    latency = {method: (metrics[method].get('avg_detection_time', 0.0) * 1000.0)
               for method in metrics}

    results = {
        'metrics': metrics,
        'confusion_matrix': {
            'y_true': y_true,
            'y_pred': y_pred,
            'labels': labels,
        },
        'latency': latency,
    }

    # Skip plot generation per request
    print("\n📊 Skipping visualization generation (disabled by request)...")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    metrics_csv_path = os.path.join(args.output, f'metrics_{timestamp}.csv')
    if pd is not None:
        pd.DataFrame(results['metrics']).to_csv(metrics_csv_path)
    else:
        # Fallback CSV writer without pandas
        metrics = results['metrics']
        methods = list(metrics.keys())
        # Collect union of metric names across methods
        metric_names = set()
        for method in methods:
            metric_names.update(metrics[method].keys())
        # Write a wide CSV: one row per metric, columns per method
        with open(metrics_csv_path, 'w', encoding='utf-8') as f:
            header = ['metric'] + methods
            f.write(','.join(header) + '\n')
            for metric_name in sorted(metric_names):
                row = [metric_name]
                for method in methods:
                    value = metrics[method].get(metric_name, '')
                    row.append(str(value))
                f.write(','.join(row) + '\n')

    print(f"\n✅ Done! Results saved to {args.output}")


if __name__ == '__main__':
    # Configure plotting style only if matplotlib is available
    if plt is not None:
        try:
            plt.style.use('seaborn-v0_8')
        except Exception:
            try:
                plt.style.use('ggplot')
            except Exception:
                plt.style.use('default')
    main()