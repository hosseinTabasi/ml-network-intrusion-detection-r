### Test-set results (official KDDTest+, not reshuffled)

Official KDDTrain+ n = 125973 (normal = 67343, attack = 58630).
Fit set after majority downsample + cap (seed = 42, cap/class = 12000): n = 24000 (normal = 12000, attack = 12000).
Official KDDTest+ n = 22544 (normal = 9711, attack = 12833).
Raw features = 23. Model columns after dummy encoding = 47.

| Model | Accuracy | Attack precision | Attack recall | Attack F1 | Normal precision | Normal recall | Normal F1 |
|-------|----------|------------------|---------------|-----------|------------------|---------------|-----------|
| rpart decision tree | 0.7826 | 0.9634 | 0.6424 | 0.7708 | 0.6719 | 0.9678 | 0.7931 |
| Random Forest (ntree = 100) | 0.7742 | 0.9677 | 0.6241 | 0.7588 | 0.6619 | 0.9725 | 0.7877 |

**Best model saved:** `rpart` (selection: highest attack recall, then attack F1, then accuracy).

Confusion matrix for rpart on KDDTest+: TN (normal→normal) = 9398, FP (normal→attack) = 313, FN (attack→normal) = 4589, TP (attack→attack) = 8244.
