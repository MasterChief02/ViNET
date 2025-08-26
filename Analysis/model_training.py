from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import pathlib
from tqdm import tqdm


PIPELINE_XGB = Pipeline([
    ("clf", XGBClassifier())
])

PIPELINE_RF = Pipeline([
    ("clf", RandomForestClassifier())
])

PIPELINE_DT = Pipeline([
    ("clf", DecisionTreeClassifier()) 
])


def group_cv_score(Xs: list[pd.DataFrame], ys: list[pd.DataFrame], pipeline: Pipeline, message: str = "", folder_to_save: str = ""):
    scores = []
    feature_names = Xs[0].columns
    message = message.replace("jio", "Jio")\
                                    .replace("airtel", "Airtel") \
                                    .replace("vilte", "ViLTE")\
                                    .replace("vinet", "ViNET") \
                                    .replace("vi", "VI") \

    # Create directory if it doesn't exist
    pathlib.Path(f"figures/{folder_to_save}").mkdir(parents=True, exist_ok=True)
    pathlib.Path(f"statistics/{folder_to_save}").mkdir(parents=True, exist_ok=True)
    pathlib.Path(f"feature_importances/{folder_to_save}").mkdir(parents=True, exist_ok=True)

    roc_fig, roc_ax = plt.subplots(figsize=(10, 8))

    max_auc = 0
    max_auc_curve = None
    max_auc_chunk = None

    for i, (X, y) in tqdm(enumerate(zip(Xs, ys)), desc=message, total=len(Xs)):
        # perform k-fold cross-validation
        # and get the average ROC AUC score
        cv = StratifiedKFold(n_splits=7, shuffle=True, random_state=42)

        fold_scores = []
        fold_feature_importance = []
        fold_curves = []
        fold_aucs = []

        for train_idx, test_idx in cv.split(X, y):
            X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
            y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

            pipeline.fit(X_train, y_train)
            y_pred = pipeline.predict(X_test)

            roc_fpr, roc_tpr, _ = roc_curve(y_test, y_pred)
            roc_auc = auc(roc_fpr, roc_tpr)

            conf_matrix = confusion_matrix(y_test, y_pred)
            fold_fpr = conf_matrix[0][1] / (conf_matrix[0][0] + conf_matrix[0][1])
            fold_tpr = conf_matrix[1][1] / (conf_matrix[1][0] + conf_matrix[1][1])

            fold_scores.append({
                "fpr": fold_fpr,
                "tpr": fold_tpr,
                "accuracy": accuracy_score(y_test, y_pred),
                "precision": precision_score(y_test, y_pred),
                "recall": recall_score(y_test, y_pred),
                "f1": f1_score(y_test, y_pred),
            })

            fold_feature_importance.append(np.array(pipeline.named_steps["clf"].feature_importances_))
            fold_curves.append((roc_fpr, roc_tpr))
            fold_aucs.append(roc_auc)
        
        mean_fpr = np.linspace(0, 1, 100)
        mean_tpr = np.zeros_like(mean_fpr) # This variable will store the sum of TPRs first
        for fpr, tpr in fold_curves:
            mean_tpr += np.interp(mean_fpr, fpr, tpr) # type: ignore

        # Assuming len(fold_curves) > 0, which is true if cv.n_splits > 0
        mean_tpr /= len(fold_curves) # Now mean_tpr stores the average TPRs
        
        mean_tpr[0] = 0.0
        mean_tpr[-1] = 1.0

        mean_auc = auc(mean_fpr, mean_tpr)

        if mean_auc > max_auc:
            max_auc = mean_auc
            max_auc_curve = (mean_fpr, mean_tpr)
            max_auc_chunk = (i + 1) * 10

        # Calculate mean of all the fold scores
        score_keys = fold_scores[0].keys()
        mean_score = {k: np.mean([s[k] for s in fold_scores]) for k in score_keys}
        mean_score = {k : np.round(100 * v, 4) for k, v in mean_score.items()}
        mean_score["chunk_length"] = (i + 1) * 10 # type: ignore
        scores.append(mean_score)

        feature_imp = np.mean(fold_feature_importance, axis=0) # type: ignore

        # only keep the top 10 features
        top_features = np.argsort(feature_imp)[-10:]
        top_feature_names = [feature_names[i] for i in top_features]
        feature_imp = feature_imp[top_features]

        # plot feature importances
        ft_imp_figure, ft_imp_ax = plt.subplots(figsize=(10, 5))
        ft_imp_ax.barh(top_feature_names, feature_imp)
        ft_imp_ax.set_xlabel("Feature Importance")
        ft_imp_ax.set_ylabel("Feature")

        save_message = message.replace(":", "").replace(" ", "_")
        save_message += f"_{(i + 1) * 10}s"

        # replace jio by Jio and airtel by Airtel, vilte ViLTE, vinet ViNET
        save_message = save_message.replace("jio", "Jio")\
                                    .replace("airtel", "Airtel") \
                                    .replace("vilte", "ViLTE")\
                                    .replace("vi", "VI") \
                                    .replace("vinet", "ViNET")


        ft_imp_ax.set_title(f"Top 10 Feature Importances for {save_message}")
        ft_imp_figure.savefig(f"feature_importances/{folder_to_save}/{save_message}_feature_importance.png", bbox_inches='tight')
        plt.close(ft_imp_figure)

    # Plot the maximum AUC curve
    if max_auc_curve:
        roc_ax.plot(max_auc_curve[0], max_auc_curve[1], label=f'Max AUC: {max_auc:.2f} (Chunk {max_auc_chunk}s)', lw=2)

    roc_ax.plot([0, 1], [0, 1], linestyle='--', lw=2, color='gray', label='Chance', alpha=.8)
    roc_ax.set_xlabel('False Positive Rate')
    roc_ax.set_ylabel('True Positive Rate')
    roc_ax.set_title(f"ROC AUC for {message}")
    roc_fig.legend()
    roc_ax.grid(True)
    roc_fig.savefig(f"figures/{folder_to_save}/{message.replace(':', '').replace(' ', '_')}_roc.png", bbox_inches='tight')
    plt.close(roc_fig)



    # Save statistics as a csv file
    df = pd.DataFrame(scores)
    clf_name = pipeline.named_steps["clf"].__class__.__name__
    df["classifier"] = clf_name
    df.to_csv(f"statistics/{folder_to_save}/{message.replace(':', '').replace(' ', '_')}_scores.csv", index=False)



class LabelGroup:
    def __init__(self):
        self._dataframes = {}
    
    def add_df(self, label: str, df: pd.DataFrame):
        self._dataframes[label] = df
        setattr(self, label, df)
    
    def __getitem__(self, label: str):
        return self._dataframes[label]

    def __iter__(self):
        for label, df in self._dataframes.items():
            yield label, df

    def __len__(self):
        return len(self._dataframes)

class ProviderGroup:
    def __init__(self):
        self.airtel = LabelGroup()
        self.jio = LabelGroup()
        self.vi = LabelGroup()

    def __getitem__(self, provider: str):
        if provider == "airtel":
            return self.airtel
        elif provider == "jio":
            return self.jio
        elif provider == "vi":
            return self.vi
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def __iter__(self):
        for provider in ["airtel", "jio", "vi"]:
            yield provider, self[provider]

    def __len__(self):
        return len(self.airtel) + len(self.jio) + len(self.vi)

class Dataset:
    """Class to load and manage datasets for different providers and chunk lengths.
    
    Two ways to access the data:

    1. self.df_chunks[10]["airtel"]["vilte"] -> DataFrame
    2. self.c10.airtel.vilte -> DataFrame
    
    """
    def __init__(self, root_dir: str):
        self.root_dir = pathlib.Path(root_dir)
        self.airtel_root = self.root_dir / "airtel"
        self.jio_root = self.root_dir / "jio"
        self.vi_root = self.root_dir / "vi"
        self.df_chunks = {}
        self.df_chunks_pl = {}


        self.chunk_lengths = [10, 20, 30, 40, 50, 60]

        for length in self.chunk_lengths:
            setattr(self, f"c{length}", ProviderGroup())
            setattr(self, f"c{length}_pl", ProviderGroup())

        self._load_data()

    def _load_data(self):
        for chunk_length in self.chunk_lengths:
            self.df_chunks[chunk_length] = {
                "airtel": {},
                "jio": {},
                "vi": {}
            }

            self.df_chunks_pl[chunk_length] = {
                "airtel": {},
                "jio": {},
                "vi": {}
            }

        
            airtel_chunk_dir = self.airtel_root / f"chunks_{chunk_length}s"
            jio_chunk_dir = self.jio_root / f"chunks_{chunk_length}s"
            vi_chunk_dir = self.vi_root / f"chunks_{chunk_length}s"
            chunk_attr = getattr(self, f"c{chunk_length}")

            for file in airtel_chunk_dir.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks[chunk_length]["airtel"][label] = df
                chunk_attr.airtel.add_df(label, df)


            for file in jio_chunk_dir.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks[chunk_length]["jio"][label] = df
                chunk_attr.jio.add_df(label, df)

            for file in vi_chunk_dir.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks[chunk_length]["vi"][label] = df
                chunk_attr.vi.add_df(label, df)
            
            airtel_chunk_dir_pl = self.airtel_root / f"chunks_{chunk_length}s_pl"
            jio_chunk_dir_pl = self.jio_root / f"chunks_{chunk_length}s_pl"
            vi_chunk_dir_pl = self.vi_root / f"chunks_{chunk_length}s_pl"
            chunk_attr_pl = getattr(self, f"c{chunk_length}_pl")

            for file in airtel_chunk_dir_pl.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks_pl[chunk_length]["airtel"][label] = df
                chunk_attr_pl.airtel.add_df(label, df)

            for file in jio_chunk_dir_pl.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks_pl[chunk_length]["jio"][label] = df
                chunk_attr_pl.jio.add_df(label, df)

            for file in vi_chunk_dir_pl.glob("*.csv"):
                df = pd.read_csv(file)
                label = "_".join(file.stem.split("_")[1:])
                self.df_chunks_pl[chunk_length]["vi"][label] = df
                chunk_attr_pl.vi.add_df(label, df)

    
    def train_across_providers(self, provider, class1, class2):
        """Report scores for all chunk lengths for a given provider and class."""
        for i in range(2): # for the two feature sets
            Xs = []
            ys = []
            for chunk_length in self.chunk_lengths:
                if i % 2 == 0:
                    df1 = self.df_chunks[chunk_length][provider][class1]
                    df2 = self.df_chunks[chunk_length][provider][class2]
                else:
                    df1 = self.df_chunks_pl[chunk_length][provider][class1]
                    df2 = self.df_chunks_pl[chunk_length][provider][class2]

                df1_X = df1.drop(columns=["label", "datetime"])
                df1_y = df1["label"]
                df1_dates = pd.to_datetime(df1["datetime"]).dt.date

                df2_X = df2.drop(columns=["label", "datetime"])
                df2_y = df2["label"]
                df2_dates = pd.to_datetime(df2["datetime"]).dt.date

                # Only consider data points such that both of them have points in the same time period
                # i.e. if df1 has some points taken at time for which df2 has no points, then remove those points
                common_dates = set(df1_dates.unique()) & set(df2_dates.unique())
                
                # Create masks for filtering
                mask1 = df1_dates.isin(common_dates)
                mask2 = df2_dates.isin(common_dates)
                
                # Apply masks to filter data
                df1_X = df1_X.loc[mask1]
                df1_y = df1_y.loc[mask1]
                df1_dates = df1_dates.loc[mask1]
                
                df2_X = df2_X.loc[mask2]
                df2_y = df2_y.loc[mask2]
                df2_dates = df2_dates.loc[mask2]

                Xs.append(pd.concat([df1_X, df2_X], axis=0, ignore_index=True))
                ys.append(pd.concat([df1_y, df2_y], axis=0, ignore_index=True))

            if i % 2 == 0:
                folder_to_save = f"summary"
                suffix_file_name = ""
            else:
                folder_to_save = f"pl"
                suffix_file_name = " pl"


            group_cv_score(Xs, ys, PIPELINE_XGB, f"{provider}: {class1} vs {class2}" + suffix_file_name, folder_to_save=folder_to_save)


if __name__ == "__main__":
    dataset = Dataset("features")
    dataset.train_across_providers("airtel", "vilte", "vinet")
    dataset.train_across_providers("jio", "vilte", "vinet")
    dataset.train_across_providers("vi", "vilte", "vinet")