/// A question to confirm before acting: title, message and the two button
/// titles, all display only. The model that asks holds the action and runs it
/// when the operator confirms.
public struct Confirmation: Sendable, Equatable {
    public var title: String
    public var message: String
    public var confirmTitle: String
    public var cancelTitle: String
    /// The confirm button discards something (give it the destructive role).
    public var isDestructive: Bool

    public init(
        title: String, message: String, confirmTitle: String, cancelTitle: String = "Cancel", isDestructive: Bool = false
    ) {
        self.title = title
        self.message = message
        self.confirmTitle = confirmTitle
        self.cancelTitle = cancelTitle
        self.isDestructive = isDestructive
    }
}
