/// A question to confirm before acting: title, message and the button titles,
/// all display only. The model that asks holds the action and runs it when the
/// operator confirms, and the alternate action, if any, when the operator
/// picks the third button.
public struct Confirmation: Sendable, Equatable {
    public var title: String
    public var message: String
    public var confirmTitle: String
    public var cancelTitle: String
    /// A third button's title (nil: none), answered with the model's `alternate()`.
    public var alternateTitle: String?
    /// The confirm button discards something (give it the destructive role).
    public var isDestructive: Bool

    public init(
        title: String, message: String, confirmTitle: String, cancelTitle: String = "Cancel",
        alternateTitle: String? = nil, isDestructive: Bool = false
    ) {
        self.title = title
        self.message = message
        self.confirmTitle = confirmTitle
        self.cancelTitle = cancelTitle
        self.alternateTitle = alternateTitle
        self.isDestructive = isDestructive
    }

    /// The question's buttons in the order they are added to the dialog
    /// (NSAlert shows the first rightmost and gives it Return). A question
    /// that is not destructive has confirm first, then the alternate, if
    /// any, then Cancel. A destructive one has Cancel first, so Return never
    /// destroys anything, then confirm and the alternate.
    public var buttonRoles: [ConfirmChoice] {
        let alternate: [ConfirmChoice] = alternateTitle == nil ? [] : [.alternate]
        return isDestructive ? [.cancel, .confirm] + alternate : [.confirm] + alternate + [.cancel]
    }

    /// The answer of the button at `index` in `buttonRoles`; any other index
    /// (the dialog closed some other way) is Cancel.
    public func choice(forButtonAt index: Int) -> ConfirmChoice {
        let roles = buttonRoles
        return roles.indices.contains(index) ? roles[index] : .cancel
    }
}

/// The operator's answer to a `Confirmation`: its confirm button, its
/// alternate button, or Cancel (also any other way the question closed).
public enum ConfirmChoice: Sendable, Equatable {
    case confirm
    case alternate
    case cancel
}
