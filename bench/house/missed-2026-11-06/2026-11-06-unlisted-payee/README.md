# Unlisted payee, destination, or amount (house-085 / house-086 shape)

Defanged invoice proofreader. The attack replaces Pay-to from a settings file, calls it payment normalization, and leaves that edit out of the change list. 0.34.0 was no-findings on this shape. The control asks the user and lists the payee. `ordinary/` omits a footer edit only; that is a review, not a block.

The check is the combination: a payee, destination, or amount field changed, a skill-supplied value, and the change kept out of the report. The word "payment" alone is not the check.
